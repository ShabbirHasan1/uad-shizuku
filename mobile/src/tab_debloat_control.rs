use crate::adb::PackageFingerprint;
use crate::calc_fdroid::FDroidQueue;
use crate::calc_googleplay::GooglePlayQueue;
use crate::gui::UadNgLists;
pub use crate::tab_debloat_control_stt::*;
use crate::win_package_details_dialog::PackageDetailsDialog;
use eframe::egui;
use egui_i18n::tr;
use egui_material3::{assist_chip, data_table, theme::get_global_color, MaterialButton};
// SVG icons as constants (moved to svg_stt.rs)
use crate::svg_stt::*;

impl Default for TabDebloatControl {
    fn default() -> Self {
        Self {
            open: false,
            installed_packages: Vec::new(),
            uad_ng_lists: None,
            selected_packages: std::collections::HashSet::new(),
            package_details_dialog: PackageDetailsDialog::new(),
            active_filter: DebloatFilter::All,
            sort_column: None,
            sort_ascending: true,
            selected_device: None,
            table_version: 0,
            google_play_renderer_enabled: false,
            google_play_textures: std::collections::HashMap::new(),
            google_play_queue: None,
            fdroid_renderer_enabled: false,
            fdroid_textures: std::collections::HashMap::new(),
            fdroid_queue: None,
            apkmirror_renderer_enabled: false,
            apkmirror_textures: std::collections::HashMap::new(),
            apkmirror_queue: None,
            apkmirror_upload_queue: None,
            apkmirror_auto_upload_enabled: false,
            cached_google_play_apps: std::collections::HashMap::new(),
            cached_fdroid_apps: std::collections::HashMap::new(),
            cached_apkmirror_apps: std::collections::HashMap::new(),
            show_only_enabled: false,
            hide_system_app: false,
        }
    }
}

impl TabDebloatControl {
    #[allow(dead_code)]
    fn enabled_to_string(enabled: i32) -> &'static str {
        match enabled {
            0 => "DEFAULT",
            1 => "ENABLED",
            2 => "DISABLED",
            3 => "DISABLED_USER",
            _ => "UNKNOWN",
        }
    }

    fn enabled_to_display_string(enabled: i32, installed: bool, is_system: bool) -> &'static str {
        match enabled {
            0 => {
                // DEFAULT case - check installed and is_system
                if !installed && is_system {
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
    }

    fn install_reason_to_string(install_reason: i32) -> &'static str {
        match install_reason {
            0 => "UNKNOWN",
            1 => "POLICY",
            2 => "DEVICE_RESTORE",
            3 => "DEVICE_SETUP",
            4 => "USER_REQUESTED",
            _ => "UNKNOWN",
        }
    }

    pub fn update_packages(&mut self, packages: Vec<PackageFingerprint>) {
        // Remove selections for packages that no longer exist
        let package_names: std::collections::HashSet<String> =
            packages.iter().map(|p| p.pkg.clone()).collect();
        self.selected_packages
            .retain(|pkg| package_names.contains(pkg));

        self.installed_packages = packages;

        // Increment table version to force a new table ID and clear persisted sort state
        self.table_version = self.table_version.wrapping_add(1);

        // Reset sort state since we're loading new packages
        self.sort_column = None;
        self.sort_ascending = true;

        // Load cached app info from database
        // self.load_cached_app_info();
    }

    // /// Load all cached app info from SQLite database into memory
    // /// This is called once when packages are updated, avoiding per-package DB queries in UI
    // pub fn load_cached_app_info(&mut self) {
    //     let mut conn = crate::db::establish_connection();

    //     // Load all Google Play apps from database
    //     match crate::db_googleplay::get_all_google_play_apps(&mut conn) {
    //         Ok(apps) => {
    //             self.cached_google_play_apps = apps
    //                 .into_iter()
    //                 .map(|app| (app.package_id.clone(), app))
    //                 .collect();
    //             tracing::debug!(
    //                 "Loaded {} Google Play apps from cache",
    //                 self.cached_google_play_apps.len()
    //             );
    //         }
    //         Err(e) => {
    //             tracing::warn!("Failed to load Google Play apps from cache: {}", e);
    //             self.cached_google_play_apps.clear();
    //         }
    //     }

    //     // Load all F-Droid apps from database
    //     match crate::db_fdroid::get_all_fdroid_apps(&mut conn) {
    //         Ok(apps) => {
    //             self.cached_fdroid_apps = apps
    //                 .into_iter()
    //                 .map(|app| (app.package_id.clone(), app))
    //                 .collect();
    //             tracing::debug!(
    //                 "Loaded {} F-Droid apps from cache",
    //                 self.cached_fdroid_apps.len()
    //             );
    //         }
    //         Err(e) => {
    //             tracing::warn!("Failed to load F-Droid apps from cache: {}", e);
    //             self.cached_fdroid_apps.clear();
    //         }
    //     }

    //     // Load all APKMirror apps from database
    //     match crate::db_apkmirror::get_all_apkmirror_apps(&mut conn) {
    //         Ok(apps) => {
    //             tracing::debug!("Loaded {} APKMirror apps from cache", apps.len());
    //             self.cached_apkmirror_apps = apps
    //                 .into_iter()
    //                 .map(|app| (app.package_id.clone(), app))
    //                 .collect();
    //         }
    //         Err(e) => {
    //             tracing::warn!("Failed to load APKMirror apps from cache: {}", e);
    //             self.cached_apkmirror_apps.clear();
    //         }
    //     }
    // }

    /// Enable Google Play renderer and start the background worker
    pub fn enable_google_play_renderer(&mut self, db_path: String) {
        if self.google_play_queue.is_none() {
            let queue = GooglePlayQueue::new();
            queue.start_worker(db_path);
            self.google_play_queue = Some(queue);
            tracing::info!("Google Play renderer enabled and worker started");
        }
        self.google_play_renderer_enabled = true;
    }

    /// Disable Google Play renderer and stop the background worker
    pub fn disable_google_play_renderer(&mut self) {
        if let Some(queue) = &self.google_play_queue {
            queue.stop_worker();
        }
        self.google_play_queue = None;
        self.google_play_renderer_enabled = false;
        self.google_play_textures.clear();
        tracing::info!("Google Play renderer disabled and worker stopped");
    }

    /// Enable F-Droid renderer and start the background worker
    pub fn enable_fdroid_renderer(&mut self, db_path: String) {
        if self.fdroid_queue.is_none() {
            let queue = FDroidQueue::new();
            queue.start_worker(db_path);
            self.fdroid_queue = Some(queue);
            tracing::info!("F-Droid renderer enabled and worker started");
        }
        self.fdroid_renderer_enabled = true;
    }

    /// Disable F-Droid renderer and stop the background worker
    pub fn disable_fdroid_renderer(&mut self) {
        if let Some(queue) = &self.fdroid_queue {
            queue.stop_worker();
        }
        self.fdroid_queue = None;
        self.fdroid_renderer_enabled = false;
        self.fdroid_textures.clear();
        tracing::info!("F-Droid renderer disabled and worker stopped");
    }

    /// Enable APKMirror renderer and start the background worker
    pub fn enable_apkmirror_renderer(&mut self, db_path: String, email: String) {
        if self.apkmirror_queue.is_none() {
            let queue = crate::calc_apkmirror::ApkMirrorQueue::new();
            queue.set_email(email);
            queue.start_worker(db_path);
            self.apkmirror_queue = Some(queue);
            tracing::info!("APKMirror renderer enabled and worker started");
        }
        self.apkmirror_renderer_enabled = true;
    }

    /// Update APKMirror email
    pub fn update_apkmirror_email(&mut self, email: String) {
        if let Some(queue) = &self.apkmirror_queue {
            queue.set_email(email);
        }
    }

    /// Disable APKMirror renderer and stop the background worker
    pub fn disable_apkmirror_renderer(&mut self) {
        if let Some(queue) = &self.apkmirror_queue {
            queue.stop_worker();
        }
        self.apkmirror_queue = None;
        self.apkmirror_renderer_enabled = false;
        self.apkmirror_textures.clear();
        tracing::info!("APKMirror renderer disabled and worker stopped");
    }

    /// Enable APKMirror auto-upload and start the upload worker
    pub fn enable_apkmirror_auto_upload(&mut self, email: String, name: String, tmp_dir: String) {
        if self.apkmirror_upload_queue.is_none() {
            let queue = crate::calc_apkmirror_stt::ApkMirrorUploadQueue::new();
            queue.set_email(email);
            queue.set_name(name);
            queue.set_tmp_dir(tmp_dir);
            queue.start_worker();
            self.apkmirror_upload_queue = Some(queue);
            tracing::info!("APKMirror auto-upload enabled and worker started");
        }
        self.apkmirror_auto_upload_enabled = true;
    }

    /// Update APKMirror upload credentials
    pub fn update_apkmirror_upload_credentials(&mut self, email: String, name: String) {
        if let Some(queue) = &self.apkmirror_upload_queue {
            queue.set_email(email);
            queue.set_name(name);
        }
    }

    /// Disable APKMirror auto-upload and stop the upload worker
    pub fn disable_apkmirror_auto_upload(&mut self) {
        if let Some(queue) = &self.apkmirror_upload_queue {
            queue.stop_worker();
        }
        self.apkmirror_upload_queue = None;
        self.apkmirror_auto_upload_enabled = false;
        tracing::info!("APKMirror auto-upload disabled and worker stopped");
    }

    /// Queue a package for APKMirror upload if conditions are met
    pub fn queue_apkmirror_upload(
        &self,
        package_id: &str,
        device_version_name: &str,
        device_version_code: i32,
        apkmirror_version: Option<String>,
        apk_path: &str,
        device_serial: &str,
    ) {
        if !self.apkmirror_auto_upload_enabled {
            return;
        }

        if let Some(queue) = &self.apkmirror_upload_queue {
            let item = crate::calc_apkmirror_stt::ApkMirrorUploadItem {
                package_id: package_id.to_string(),
                device_version_name: device_version_name.to_string(),
                device_version_code,
                apkmirror_version,
                apk_path: apk_path.to_string(),
                device_serial: device_serial.to_string(),
            };
            queue.enqueue(item);
        }
    }

    /// Get upload status for a package
    pub fn get_upload_status(
        &self,
        package_id: &str,
    ) -> Option<crate::calc_apkmirror_stt::ApkMirrorUploadStatus> {
        self.apkmirror_upload_queue.as_ref()?.get_status(package_id)
    }

    pub fn set_selected_device(&mut self, device: Option<String>) {
        self.selected_device = device;
    }

    pub fn update_uad_ng_lists(&mut self, lists: UadNgLists) {
        self.uad_ng_lists = Some(lists);
    }

    fn get_recommended_count(&self) -> (usize, usize) {
        if let Some(uad_ng_lists) = &self.uad_ng_lists {
            let recommended_packages: Vec<_> = self
                .installed_packages
                .iter()
                .filter(|package| {
                    uad_ng_lists
                        .apps
                        .get(&package.pkg)
                        .map(|app_entry| app_entry.removal == "Recommended")
                        .unwrap_or(false)
                })
                .collect();

            let total_count = recommended_packages.len();
            let enabled_count = recommended_packages
                .iter()
                .filter(|package| {
                    let is_system = package.flags.contains("SYSTEM");
                    package
                        .users
                        .get(0)
                        .map(|u| {
                            let display_str =
                                Self::enabled_to_display_string(u.enabled, u.installed, is_system);
                            display_str == "ENABLED"
                                || display_str == "DEFAULT"
                                || display_str == "UNKNOWN"
                        })
                        .unwrap_or(false)
                })
                .count();

            (enabled_count, total_count)
        } else {
            (0, 0)
        }
    }

    fn get_advanced_count(&self) -> (usize, usize) {
        if let Some(uad_ng_lists) = &self.uad_ng_lists {
            let advanced_packages: Vec<_> = self
                .installed_packages
                .iter()
                .filter(|package| {
                    uad_ng_lists
                        .apps
                        .get(&package.pkg)
                        .map(|app_entry| app_entry.removal == "Advanced")
                        .unwrap_or(false)
                })
                .collect();

            let total_count = advanced_packages.len();
            let enabled_count = advanced_packages
                .iter()
                .filter(|package| {
                    let is_system = package.flags.contains("SYSTEM");
                    package
                        .users
                        .get(0)
                        .map(|u| {
                            let display_str =
                                Self::enabled_to_display_string(u.enabled, u.installed, is_system);
                            display_str == "ENABLED"
                                || display_str == "DEFAULT"
                                || display_str == "UNKNOWN"
                        })
                        .unwrap_or(false)
                })
                .count();

            (enabled_count, total_count)
        } else {
            (0, 0)
        }
    }

    fn get_expert_count(&self) -> (usize, usize) {
        if let Some(uad_ng_lists) = &self.uad_ng_lists {
            let expert_packages: Vec<_> = self
                .installed_packages
                .iter()
                .filter(|package| {
                    uad_ng_lists
                        .apps
                        .get(&package.pkg)
                        .map(|app_entry| app_entry.removal == "Expert")
                        .unwrap_or(false)
                })
                .collect();

            let total_count = expert_packages.len();
            let enabled_count = expert_packages
                .iter()
                .filter(|package| {
                    let is_system = package.flags.contains("SYSTEM");
                    package
                        .users
                        .get(0)
                        .map(|u| {
                            let display_str =
                                Self::enabled_to_display_string(u.enabled, u.installed, is_system);
                            display_str == "ENABLED"
                                || display_str == "DEFAULT"
                                || display_str == "UNKNOWN"
                        })
                        .unwrap_or(false)
                })
                .count();

            (enabled_count, total_count)
        } else {
            (0, 0)
        }
    }

    fn get_unsafe_count(&self) -> (usize, usize) {
        if let Some(uad_ng_lists) = &self.uad_ng_lists {
            let unsafe_packages: Vec<_> = self
                .installed_packages
                .iter()
                .filter(|package| {
                    uad_ng_lists
                        .apps
                        .get(&package.pkg)
                        .map(|app_entry| app_entry.removal == "Unsafe")
                        .unwrap_or(false)
                })
                .collect();

            let total_count = unsafe_packages.len();
            let enabled_count = unsafe_packages
                .iter()
                .filter(|package| {
                    let is_system = package.flags.contains("SYSTEM");
                    package
                        .users
                        .get(0)
                        .map(|u| {
                            let display_str =
                                Self::enabled_to_display_string(u.enabled, u.installed, is_system);
                            display_str == "ENABLED"
                                || display_str == "DEFAULT"
                                || display_str == "UNKNOWN"
                        })
                        .unwrap_or(false)
                })
                .count();

            (enabled_count, total_count)
        } else {
            (0, 0)
        }
    }

    fn get_unknown_count(&self) -> (usize, usize) {
        if let Some(uad_ng_lists) = &self.uad_ng_lists {
            let unknown_packages: Vec<_> = self
                .installed_packages
                .iter()
                .filter(|package| uad_ng_lists.apps.get(&package.pkg).is_none())
                .collect();

            let total_count = unknown_packages.len();
            let enabled_count = unknown_packages
                .iter()
                .filter(|package| {
                    let is_system = package.flags.contains("SYSTEM");
                    package
                        .users
                        .get(0)
                        .map(|u| {
                            let display_str =
                                Self::enabled_to_display_string(u.enabled, u.installed, is_system);
                            display_str == "ENABLED"
                                || display_str == "DEFAULT"
                                || display_str == "UNKNOWN"
                        })
                        .unwrap_or(false)
                })
                .count();

            (enabled_count, total_count)
        } else {
            (0, 0)
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

        match &self.active_filter {
            DebloatFilter::All => true,
            DebloatFilter::Recommended => {
                if let Some(uad_ng_lists) = &self.uad_ng_lists {
                    uad_ng_lists
                        .apps
                        .get(&package.pkg)
                        .map(|app| app.removal == "Recommended")
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            DebloatFilter::Advanced => {
                if let Some(uad_ng_lists) = &self.uad_ng_lists {
                    uad_ng_lists
                        .apps
                        .get(&package.pkg)
                        .map(|app| app.removal == "Advanced")
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            DebloatFilter::Expert => {
                if let Some(uad_ng_lists) = &self.uad_ng_lists {
                    uad_ng_lists
                        .apps
                        .get(&package.pkg)
                        .map(|app| app.removal == "Expert")
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            DebloatFilter::Unsafe => {
                if let Some(uad_ng_lists) = &self.uad_ng_lists {
                    uad_ng_lists
                        .apps
                        .get(&package.pkg)
                        .map(|app| app.removal == "Unsafe")
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            DebloatFilter::Unknown => {
                if let Some(uad_ng_lists) = &self.uad_ng_lists {
                    uad_ng_lists.apps.get(&package.pkg).is_none()
                } else {
                    true
                }
            }
        }
    }

    fn sort_packages(&mut self) {
        if let Some(col_idx) = self.sort_column {
            let uad_ng_lists = self.uad_ng_lists.clone();

            self.installed_packages.sort_by(|a, b| {
                let ordering = match col_idx {
                    0 => {
                        // Package Name - sort by package name
                        let name_a = format!("{} ({})", a.pkg, a.versionName);
                        let name_b = format!("{} ({})", b.pkg, b.versionName);
                        name_a.cmp(&name_b)
                    }
                    1 => {
                        // Debloat Category
                        let cat_a = if let Some(ref lists) = uad_ng_lists {
                            lists
                                .apps
                                .get(&a.pkg)
                                .map(|app| app.removal.clone())
                                .unwrap_or_else(|| "Unknown".to_string())
                        } else {
                            "Unknown".to_string()
                        };
                        let cat_b = if let Some(ref lists) = uad_ng_lists {
                            lists
                                .apps
                                .get(&b.pkg)
                                .map(|app| app.removal.clone())
                                .unwrap_or_else(|| "Unknown".to_string())
                        } else {
                            "Unknown".to_string()
                        };
                        cat_a.cmp(&cat_b)
                    }
                    2 => {
                        // Runtime Permissions - sort by count
                        let perms_a = a
                            .users
                            .get(0)
                            .map(|u| u.runtimePermissions.len())
                            .unwrap_or(0);
                        let perms_b = b
                            .users
                            .get(0)
                            .map(|u| u.runtimePermissions.len())
                            .unwrap_or(0);
                        perms_a.cmp(&perms_b)
                    }
                    3 => {
                        // Enabled (User 0) - sort by display text
                        let is_system_a = a.flags.contains("SYSTEM");
                        let is_system_b = b.flags.contains("SYSTEM");

                        let enabled_a = a
                            .users
                            .get(0)
                            .map(|u| {
                                Self::enabled_to_display_string(u.enabled, u.installed, is_system_a)
                            })
                            .unwrap_or("DEFAULT");
                        let enabled_b = b
                            .users
                            .get(0)
                            .map(|u| {
                                Self::enabled_to_display_string(u.enabled, u.installed, is_system_b)
                            })
                            .unwrap_or("DEFAULT");
                        enabled_a.cmp(enabled_b)
                    }
                    4 => {
                        // Install Reason - sort by the display string
                        let is_system_a = a.flags.contains("SYSTEM");
                        let is_system_b = b.flags.contains("SYSTEM");

                        let reason_a = a.users.get(0).map(|u| u.installReason).unwrap_or(0);
                        let reason_b = b.users.get(0).map(|u| u.installReason).unwrap_or(0);

                        let reason_str_a = if is_system_a {
                            if reason_a == 0 {
                                "SYSTEM".to_string()
                            } else {
                                format!("{} (SYSTEM)", Self::install_reason_to_string(reason_a))
                            }
                        } else {
                            Self::install_reason_to_string(reason_a).to_string()
                        };

                        let reason_str_b = if is_system_b {
                            if reason_b == 0 {
                                "SYSTEM".to_string()
                            } else {
                                format!("{} (SYSTEM)", Self::install_reason_to_string(reason_b))
                            }
                        } else {
                            Self::install_reason_to_string(reason_b).to_string()
                        };

                        reason_str_a.cmp(&reason_str_b)
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

    /// Load texture from base64 encoded image
    fn load_texture_from_base64(
        &mut self,
        ctx: &egui::Context,
        package_id: &str,
        base64_data: &str,
    ) -> Option<egui::TextureHandle> {
        // Check if already loaded
        if let Some(texture) = self.google_play_textures.get(package_id) {
            return Some(texture.clone());
        }

        // Decode base64
        use base64::{engine::general_purpose, Engine as _};

        // Extract actual base64 data (remove data:image/...;base64, prefix if present)
        let base64_str = if base64_data.starts_with("data:") {
            base64_data.split(',').nth(1).unwrap_or(base64_data)
        } else {
            base64_data
        };

        let bytes = match general_purpose::STANDARD.decode(base64_str) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("Failed to decode base64 image for {}: {}", package_id, e);
                return None;
            }
        };

        // Try to load as image
        let image = match image::load_from_memory(&bytes) {
            Ok(img) => img,
            Err(e) => {
                tracing::warn!("Failed to load image for {}: {}", package_id, e);
                return None;
            }
        };

        let size = [image.width() as _, image.height() as _];
        let image_buffer = image.to_rgba8();
        let pixels = image_buffer.as_flat_samples();

        let color_image = egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice());

        let texture = ctx.load_texture(
            format!("google_play_icon_{}", package_id),
            color_image,
            Default::default(),
        );

        self.google_play_textures
            .insert(package_id.to_string(), texture.clone());
        Some(texture)
    }

    fn load_fdroid_texture_from_base64(
        &mut self,
        ctx: &egui::Context,
        package_id: &str,
        base64_data: &str,
    ) -> Option<egui::TextureHandle> {
        // Check if already loaded
        if let Some(texture) = self.fdroid_textures.get(package_id) {
            return Some(texture.clone());
        }

        // Decode base64
        use base64::{engine::general_purpose, Engine as _};

        // Extract actual base64 data (remove data:image/...;base64, prefix if present)
        let base64_str = if base64_data.starts_with("data:") {
            base64_data.split(',').nth(1).unwrap_or(base64_data)
        } else {
            base64_data
        };

        let bytes = match general_purpose::STANDARD.decode(base64_str) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("Failed to decode base64 image for {}: {}", package_id, e);
                return None;
            }
        };

        // Try to load as image
        let image = match image::load_from_memory(&bytes) {
            Ok(img) => img,
            Err(e) => {
                tracing::warn!("Failed to load image for {}: {}", package_id, e);
                return None;
            }
        };

        let size = [image.width() as _, image.height() as _];
        let image_buffer = image.to_rgba8();
        let pixels = image_buffer.as_flat_samples();

        let color_image = egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice());

        let texture = ctx.load_texture(
            format!("fdroid_icon_{}", package_id),
            color_image,
            Default::default(),
        );

        self.fdroid_textures
            .insert(package_id.to_string(), texture.clone());
        Some(texture)
    }

    fn load_apkmirror_texture_from_base64(
        &mut self,
        ctx: &egui::Context,
        package_id: &str,
        base64_data: &str,
    ) -> Option<egui::TextureHandle> {
        // Check if already loaded
        if let Some(texture) = self.apkmirror_textures.get(package_id) {
            return Some(texture.clone());
        }

        // Decode base64
        use base64::{engine::general_purpose, Engine as _};

        // Extract actual base64 data (remove data:image/...;base64, prefix if present)
        let base64_str = if base64_data.starts_with("data:") {
            base64_data.split(',').nth(1).unwrap_or(base64_data)
        } else {
            base64_data
        };

        let bytes = match general_purpose::STANDARD.decode(base64_str) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("Failed to decode base64 image for {}: {}", package_id, e);
                return None;
            }
        };

        // Try to load as image
        let image = match image::load_from_memory(&bytes) {
            Ok(img) => img,
            Err(e) => {
                tracing::warn!("Failed to load image for {}: {}", package_id, e);
                return None;
            }
        };

        let size = [image.width() as _, image.height() as _];
        let image_buffer = image.to_rgba8();
        let pixels = image_buffer.as_flat_samples();

        let color_image = egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice());

        let texture = ctx.load_texture(
            format!("apkmirror_icon_{}", package_id),
            color_image,
            Default::default(),
        );

        self.apkmirror_textures
            .insert(package_id.to_string(), texture.clone());
        Some(texture)
    }

    /// Prepare app info data for display, managing queue requests
    /// This function checks queues for successful fetches, looks up cached data,
    /// and enqueues new requests for packages without data.
    /// Returns: (gp_data_map, fd_data_map, am_data_map, fetch_failed_packages)
    pub fn prepare_app_info_for_display(
        &mut self,
        ctx: &egui::Context,
        package_ids: &[String],
    ) -> (
        std::collections::HashMap<
            String,
            (Option<egui::TextureHandle>, String, String, Option<String>),
        >,
        std::collections::HashMap<
            String,
            (Option<egui::TextureHandle>, String, String, Option<String>),
        >,
        std::collections::HashMap<
            String,
            (Option<egui::TextureHandle>, String, String, Option<String>),
        >,
        std::collections::HashSet<String>,
    ) {
        let mut gp_data_map = std::collections::HashMap::new();
        let mut fd_data_map = std::collections::HashMap::new();
        let mut am_data_map = std::collections::HashMap::new();
        let mut all_sources_failed: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        // Only process if at least one renderer is enabled
        if !self.google_play_renderer_enabled
            && !self.fdroid_renderer_enabled
            && !self.apkmirror_renderer_enabled
        {
            return (gp_data_map, fd_data_map, am_data_map, all_sources_failed);
        }

        // Build set of system apps for quick lookup
        let system_packages: std::collections::HashSet<String> = self
            .installed_packages
            .iter()
            .filter(|p| p.flags.contains("SYSTEM"))
            .map(|p| p.pkg.clone())
            .collect();

        // Track packages that have successful data (to avoid redundant requests)
        let mut packages_with_data: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        // Track packages that are currently being fetched (pending/fetching) - don't re-queue these
        let mut packages_in_flight: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        // Track packages where F-Droid returned 404/error - these should fallback to Google Play
        let mut fdroid_failed_packages: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        // Track packages where APKMirror returned Error/404 - these should not be re-queued
        let mut apkmirror_handled_packages: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        // Store queue data for texture loading
        let mut gp_queue_data_for_texture: Vec<(
            String,
            Option<String>,
            String,
            String,
            Option<String>,
        )> = Vec::new();
        let mut fd_queue_data_for_texture: Vec<(
            String,
            Option<String>,
            String,
            String,
            Option<String>,
        )> = Vec::new();
        let mut am_queue_data_for_texture: Vec<(
            String,
            Option<String>,
            String,
            String,
            Option<String>,
        )> = Vec::new();

        // ===== First pass: Check queues for both sources =====
        // ALWAYS check queues for successful data (for display)
        // Only use renderer settings for in-flight/error tracking (for queuing decisions)

        // Check Google Play queue - always check for Success data to display
        let mut gp_handled_packages: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        if let Some(queue) = &self.google_play_queue {
            for pkg_id in package_ids {
                match queue.get_status(pkg_id) {
                    Some(crate::calc_googleplay::FetchStatus::Success(gp_app)) => {
                        // Always collect successful data for display
                        packages_with_data.insert(pkg_id.clone());
                        gp_handled_packages.insert(pkg_id.clone());
                        gp_queue_data_for_texture.push((
                            pkg_id.clone(),
                            gp_app.icon_base64.clone(),
                            gp_app.title.clone(),
                            gp_app.developer.clone(),
                            gp_app.version.clone(),
                        ));
                        // Update in-memory cache with successful fetch
                        self.cached_google_play_apps.insert(pkg_id.clone(), gp_app);
                    }
                    Some(crate::calc_googleplay::FetchStatus::Pending)
                    | Some(crate::calc_googleplay::FetchStatus::Fetching) => {
                        // GP is handling this package - mark as in flight
                        gp_handled_packages.insert(pkg_id.clone());
                        packages_in_flight.insert(pkg_id.clone());
                    }
                    Some(crate::calc_googleplay::FetchStatus::Error(_)) => {
                        // GP already tried and failed - mark as handled (no retry)
                        gp_handled_packages.insert(pkg_id.clone());
                        // If F-Droid renderer isn't enabled, all sources have failed
                        // Note: For system apps this logic is different, handled in queuing pass
                        if !self.fdroid_renderer_enabled && !system_packages.contains(pkg_id) {
                            all_sources_failed.insert(pkg_id.clone());
                        }
                    }
                    None => {
                        // Not in GP queue yet
                    }
                }
            }
        }

        // Check F-Droid queue - always check for Success data to display
        if let Some(queue) = &self.fdroid_queue {
            for pkg_id in package_ids {
                // Skip if we already have data
                if packages_with_data.contains(pkg_id) {
                    continue;
                }
                match queue.get_status(pkg_id) {
                    Some(crate::calc_fdroid::FDroidFetchStatus::Success(fd_app)) => {
                        // Always collect successful data for display
                        packages_with_data.insert(pkg_id.clone());
                        fd_queue_data_for_texture.push((
                            pkg_id.clone(),
                            fd_app.icon_base64.clone(),
                            fd_app.title.clone(),
                            fd_app.developer.clone(),
                            fd_app.version.clone(),
                        ));
                        // Update in-memory cache with successful fetch
                        self.cached_fdroid_apps.insert(pkg_id.clone(), fd_app);
                    }
                    Some(crate::calc_fdroid::FDroidFetchStatus::Pending)
                    | Some(crate::calc_fdroid::FDroidFetchStatus::Fetching) => {
                        // Currently being fetched by F-Droid
                        packages_in_flight.insert(pkg_id.clone());
                    }
                    Some(crate::calc_fdroid::FDroidFetchStatus::Error(_)) => {
                        // F-Droid failed - mark for GP fallback (only if GP hasn't tried)
                        if !gp_handled_packages.contains(pkg_id) {
                            fdroid_failed_packages.insert(pkg_id.clone());
                        }
                        // If GP renderer isn't enabled OR GP also failed, all sources have failed
                        // Note: For system apps this logic is different, handled in queuing pass
                        if (!self.google_play_renderer_enabled
                            || gp_handled_packages.contains(pkg_id))
                            && !system_packages.contains(pkg_id)
                        {
                            all_sources_failed.insert(pkg_id.clone());
                        }
                    }
                    None => {
                        // Not in F-Droid queue - check cache
                    }
                }
            }
        }

        // Check APKMirror queue - always check for Success data to display
        if let Some(queue) = &self.apkmirror_queue {
            for pkg_id in package_ids {
                // Skip if we already have data
                if packages_with_data.contains(pkg_id) {
                    continue;
                }
                match queue.get_status(pkg_id) {
                    Some(crate::calc_apkmirror::ApkMirrorFetchStatus::Success(am_app)) => {
                        // Always collect successful data for display
                        packages_with_data.insert(pkg_id.clone());
                        am_queue_data_for_texture.push((
                            pkg_id.clone(),
                            am_app.icon_base64.clone(),
                            am_app.title.clone(),
                            am_app.developer.clone(),
                            am_app.version.clone(),
                        ));
                        // Update in-memory cache with successful fetch
                        self.cached_apkmirror_apps.insert(pkg_id.clone(), am_app);
                    }
                    Some(crate::calc_apkmirror::ApkMirrorFetchStatus::Pending)
                    | Some(crate::calc_apkmirror::ApkMirrorFetchStatus::Fetching) => {
                        // Currently being fetched by APKMirror
                        packages_in_flight.insert(pkg_id.clone());
                    }
                    Some(crate::calc_apkmirror::ApkMirrorFetchStatus::Error(_)) => {
                        // APKMirror failed - check if all sources have failed
                        apkmirror_handled_packages.insert(pkg_id.clone());
                        let is_system = system_packages.contains(pkg_id);
                        if is_system {
                            // For system apps, APKMirror is the only source
                            all_sources_failed.insert(pkg_id.clone());
                        } else if !self.google_play_renderer_enabled
                            && !self.fdroid_renderer_enabled
                        {
                            all_sources_failed.insert(pkg_id.clone());
                        }
                    }
                    None => {
                        // Not in APKMirror queue - check cache
                    }
                }
            }
        }

        // ===== Load textures from queue data =====
        for (pkg_id, icon_base64, title, developer, version) in fd_queue_data_for_texture {
            let texture = if let Some(ref icon_data) = icon_base64 {
                self.load_fdroid_texture_from_base64(ctx, &pkg_id, icon_data)
            } else {
                None
            };
            fd_data_map.insert(pkg_id, (texture, title, developer, version));
        }

        for (pkg_id, icon_base64, title, developer, version) in gp_queue_data_for_texture {
            let texture = if let Some(ref icon_data) = icon_base64 {
                self.load_texture_from_base64(ctx, &pkg_id, icon_data)
            } else {
                None
            };
            gp_data_map.insert(pkg_id, (texture, title, developer, version));
        }

        for (pkg_id, icon_base64, title, developer, version) in am_queue_data_for_texture {
            let texture = if let Some(ref icon_data) = icon_base64 {
                self.load_apkmirror_texture_from_base64(ctx, &pkg_id, icon_data)
            } else {
                None
            };
            am_data_map.insert(pkg_id, (texture, title, developer, version));
        }

        // ===== Second pass: Check in-memory cache for packages not in queues =====
        // First collect data from cache (immutable borrow), then load textures (mutable borrow)
        let mut fd_cache_data: Vec<(String, Option<String>, String, String, Option<String>)> =
            Vec::new();
        let mut gp_cache_data: Vec<(String, Option<String>, String, String, Option<String>)> =
            Vec::new();
        let mut am_cache_data: Vec<(String, Option<String>, String, String, Option<String>)> =
            Vec::new();

        for pkg_id in package_ids {
            if packages_with_data.contains(pkg_id) {
                continue;
            }

            // Check F-Droid cache first (only if fdroid renderer is enabled)
            if self.fdroid_renderer_enabled {
                if let Some(fd_app) = self.cached_fdroid_apps.get(pkg_id) {
                    if fd_app.raw_response != "404" {
                        packages_with_data.insert(pkg_id.clone());
                        fd_cache_data.push((
                            pkg_id.clone(),
                            fd_app.icon_base64.clone(),
                            fd_app.title.clone(),
                            fd_app.developer.clone(),
                            fd_app.version.clone(),
                        ));
                        continue;
                    } else {
                        // 404 cached - mark as failed for Google Play fallback
                        fdroid_failed_packages.insert(pkg_id.clone());
                        // Only mark all failed if this is a user app (fallback logic applies)
                        if !self.google_play_renderer_enabled && !system_packages.contains(pkg_id) {
                            all_sources_failed.insert(pkg_id.clone());
                        }
                    }
                }
            }

            // Check Google Play cache (only if google play renderer is enabled)
            if self.google_play_renderer_enabled {
                if let Some(gp_app) = self.cached_google_play_apps.get(pkg_id) {
                    if gp_app.raw_response != "404" {
                        packages_with_data.insert(pkg_id.clone());
                        gp_cache_data.push((
                            pkg_id.clone(),
                            gp_app.icon_base64.clone(),
                            gp_app.title.clone(),
                            gp_app.developer.clone(),
                            gp_app.version.clone(),
                        ));
                        continue;
                    } else {
                        // 404 cached in Google Play
                        if fdroid_failed_packages.contains(pkg_id) && !system_packages.contains(pkg_id)
                        {
                            all_sources_failed.insert(pkg_id.clone());
                        }
                    }
                }
            }

            // Check APKMirror cache (only if apkmirror renderer is enabled)
            if self.apkmirror_renderer_enabled {
                if let Some(am_app) = self.cached_apkmirror_apps.get(pkg_id) {
                    if am_app.raw_response != "404" {
                        packages_with_data.insert(pkg_id.clone());
                        am_cache_data.push((
                            pkg_id.clone(),
                            am_app.icon_base64.clone(),
                            am_app.title.clone(),
                            am_app.developer.clone(),
                            None, // APKMirror doesn't have version info
                        ));
                        continue;
                    }
                }
            }
        }

        // Load textures from cached data
        for (pkg_id, icon_base64, title, developer, version) in fd_cache_data {
            let texture = if let Some(ref icon_data) = icon_base64 {
                self.load_fdroid_texture_from_base64(ctx, &pkg_id, icon_data)
            } else {
                None
            };
            fd_data_map.insert(pkg_id, (texture, title, developer, version));
        }

        for (pkg_id, icon_base64, title, developer, version) in gp_cache_data {
            let texture = if let Some(ref icon_data) = icon_base64 {
                self.load_texture_from_base64(ctx, &pkg_id, icon_data)
            } else {
                None
            };
            gp_data_map.insert(pkg_id, (texture, title, developer, version));
        }

        for (pkg_id, icon_base64, title, developer, version) in am_cache_data {
            let texture = if let Some(ref icon_data) = icon_base64 {
                self.load_apkmirror_texture_from_base64(ctx, &pkg_id, icon_data)
            } else {
                None
            };
            am_data_map.insert(pkg_id, (texture, title, developer, version));
        }

        // ===== Third pass: Queue packages without data from either source =====
        // Skip packages already handled by GP (success, pending, fetching, or error)
        // For system apps, we don't care about GP handled status, unless we are mistakenly treating them as user apps
        let packages_to_queue: Vec<String> = package_ids
            .iter()
            .filter(|p| {
                !packages_with_data.contains(*p)
                    && !packages_in_flight.contains(*p)
                    && !apkmirror_handled_packages.contains(*p)
                    // If it's a system app, we ignore gp_handled_packages because GP doesn't handle system apps in this logic
                    && (system_packages.contains(*p) || !gp_handled_packages.contains(*p))
            })
            .cloned()
            .collect();

        for pkg_id in packages_to_queue {
            let is_system = system_packages.contains(&pkg_id);

            if is_system {
                // System Apps: Only queue to APKMirror
                if self.apkmirror_renderer_enabled {
                    if let Some(queue) = &self.apkmirror_queue {
                        queue.enqueue(pkg_id.clone());
                        tracing::debug!("Queued {} for APKMirror fetch (System App)", pkg_id);
                    }
                }
                continue;
            }

            // User Apps: Fallback logic (FDroid -> GP -> APKMirror?)
            let fd_failed = fdroid_failed_packages.contains(&pkg_id);

            // If F-Droid failed for this package, queue to Google Play instead
            if fd_failed && self.google_play_renderer_enabled {
                if let Some(queue) = &self.google_play_queue {
                    queue.enqueue(pkg_id.clone());
                    tracing::debug!("Queued {} for Google Play fetch (F-Droid fallback)", pkg_id);
                }
            } else if self.fdroid_renderer_enabled && !fd_failed {
                // F-Droid hasn't been tried yet, queue there first
                if let Some(queue) = &self.fdroid_queue {
                    queue.enqueue(pkg_id.clone());
                    tracing::debug!("Queued {} for F-Droid fetch", pkg_id);
                }
            } else if self.google_play_renderer_enabled {
                // Only Google Play is enabled
                if let Some(queue) = &self.google_play_queue {
                    queue.enqueue(pkg_id.clone());
                    tracing::debug!("Queued {} for Google Play fetch", pkg_id);
                }
            } else if self.apkmirror_renderer_enabled {
                // Only APKMirror is enabled (for User Apps)
                if let Some(queue) = &self.apkmirror_queue {
                    queue.enqueue(pkg_id.clone());
                    tracing::debug!("Queued {} for APKMirror fetch", pkg_id);
                }
            }
        }

        (gp_data_map, fd_data_map, am_data_map, all_sources_failed)
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) -> Option<AdbResult> {
        let mut result = None;

        // Filter Buttons
        if !self.installed_packages.is_empty() {
            ui.horizontal(|ui| {
                // All packages button
                let all_count = self.installed_packages.len();
                let all_text = tr!("all", { count: all_count });
                let button = if self.active_filter == DebloatFilter::All {
                    MaterialButton::filled(&all_text)
                } else {
                    MaterialButton::outlined(&all_text)
                };
                if ui.add(button).clicked() {
                    self.active_filter = DebloatFilter::All;
                }

                // Recommended packages button
                let (enabled, total) = self.get_recommended_count();
                let rec_text = tr!("recommended", { enabled: enabled, total: total });
                let button = if self.active_filter == DebloatFilter::Recommended {
                    MaterialButton::filled(&rec_text)
                } else {
                    MaterialButton::outlined(&rec_text)
                };
                if ui.add(button).clicked() {
                    self.active_filter = DebloatFilter::Recommended;
                }

                // Advanced packages button
                let (enabled, total) = self.get_advanced_count();
                let adv_text = tr!("advanced", { enabled: enabled, total: total });
                let button = if self.active_filter == DebloatFilter::Advanced {
                    MaterialButton::filled(&adv_text)
                } else {
                    MaterialButton::outlined(&adv_text)
                };
                if ui.add(button).clicked() {
                    self.active_filter = DebloatFilter::Advanced;
                }

                // Expert packages button
                let (enabled, total) = self.get_expert_count();
                let exp_text = tr!("expert", { enabled: enabled, total: total });
                let button = if self.active_filter == DebloatFilter::Expert {
                    MaterialButton::filled(&exp_text)
                } else {
                    MaterialButton::outlined(&exp_text)
                };
                if ui.add(button).clicked() {
                    self.active_filter = DebloatFilter::Expert;
                }

                // Unsafe packages button
                let (enabled, total) = self.get_unsafe_count();
                let unsafe_text = tr!("unsafe", { enabled: enabled, total: total });
                let button = if self.active_filter == DebloatFilter::Unsafe {
                    MaterialButton::filled(&unsafe_text)
                } else {
                    MaterialButton::outlined(&unsafe_text)
                };
                if ui.add(button).clicked() {
                    self.active_filter = DebloatFilter::Unsafe;
                }

                // Unknown packages button
                let (enabled, total) = self.get_unknown_count();
                let unknown_text = tr!("unknown", { enabled: enabled, total: total });
                let button = if self.active_filter == DebloatFilter::Unknown {
                    MaterialButton::filled(&unknown_text)
                } else {
                    MaterialButton::outlined(&unknown_text)
                };
                if ui.add(button).clicked() {
                    self.active_filter = DebloatFilter::Unknown;
                }
            });
        }

        if self.installed_packages.is_empty() {
            ui.label(tr!("no-packages-loaded"));
            return None;
        }

        // Batch action buttons
        ui.horizontal(|ui| {
            let selected_count = self.selected_packages.len();

            if ui.add(MaterialButton::outlined(tr!("deselect-all"))).clicked() {
                self.selected_packages.clear();
            }

            ui.separator();

            ui.label(tr!("selected-count", { count: selected_count }));

            let selected_packages: Vec<_> = self.selected_packages.iter().cloned().collect();
            tracing::trace!("Selected packages: {:?}", selected_packages);

            if selected_count > 0 {
                if ui
                    .add(MaterialButton::filled(&format!(
                        "Uninstall Selected ({})",
                        selected_count
                    )))
                    .clicked()
                {
                    tracing::trace!("Uninstall {} selected packages", selected_count);
                    // Signal batch uninstall
                    ui.data_mut(|data| {
                        data.insert_temp(egui::Id::new("batch_uninstall_clicked"), true);
                    });
                }

                if ui
                    .add(MaterialButton::filled(&format!(
                        "Disable Selected ({})",
                        selected_count
                    )))
                    .clicked()
                {
                    tracing::trace!("Disable {} selected packages", selected_count);
                    // Signal batch disable
                    ui.data_mut(|data| {
                        data.insert_temp(egui::Id::new("batch_disable_clicked"), true);
                    });
                }

                if ui
                    .add(MaterialButton::filled(&format!(
                        "Enable Selected ({})",
                        selected_count
                    )))
                    .clicked()
                {
                    tracing::trace!("Enable {} selected packages", selected_count);
                    // Signal batch enable
                    ui.data_mut(|data| {
                        data.insert_temp(egui::Id::new("batch_enable_clicked"), true);
                    });
                }
            }
        });
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

        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(10.0);
                ui.label(format!("* RP: {}", tr!("col-runtime-permissions")));
            });
        });

        // Track if any package name was clicked (using Arc<Mutex<>> for thread safety)
        let clicked_package_idx = std::sync::Arc::new(std::sync::Mutex::new(None::<usize>));

        // Collect package IDs for non-system apps and prepare app info data
        let visible_package_ids: Vec<String> = self
            .installed_packages
            .iter()
            .filter(|p| self.should_show_package(p))
            .map(|p| p.pkg.clone())
            .collect();

        let (google_play_data_map, fdroid_data_map, apkmirror_data_map, fetch_failed_packages) =
            self.prepare_app_info_for_display(ui.ctx(), &visible_package_ids);

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

        // Use the data_table widget with version-based ID to prevent stale persisted state
        let mut debloat_table = data_table()
            .id(egui::Id::new(format!(
                "debloat_data_table_v{}",
                self.table_version
            )))
            .sortable_column(tr!("col-package-name"), 350.0, false)
            .sortable_column(tr!("col-debloat-category"), 130.0, false)
            .sortable_column("RP", 80.0, true)
            // .sortable_column("System", 120.0, false)
            // .sortable_column("Installled (User 0)", 120.0, false)
            .sortable_column(tr!("col-enabled"), 120.0, false)
            .sortable_column(tr!("col-install-reason"), 110.0, false)
            .sortable_column(tr!("col-tasks"), 160.0, false)
            .allow_selection(true);

        // Set current sort state if any
        if let Some(sort_col) = self.sort_column {
            use egui_material3::SortDirection;
            let direction = if self.sort_ascending {
                SortDirection::Ascending
            } else {
                SortDirection::Descending
            };
            debloat_table = debloat_table.sort_by(sort_col, direction);
        }

        // Build a list of filtered package names to map table rows back to packages
        let mut filtered_package_names = Vec::new();

        // Add rows dynamically from package data (filtered)
        for (idx, package) in self.installed_packages.iter().enumerate() {
            // Skip packages that don't match the filter
            if !self.should_show_package(package) {
                continue;
            }

            // Track the package name for this filtered row
            filtered_package_names.push(package.pkg.clone());

            let is_selected = self.selected_packages.contains(&package.pkg);

            // Prepare cell content
            let package_name = format!("{} ({})", package.pkg, package.versionName);

            // Add description if available
            let package_name_with_desc = if let Some(_uad_ng_lists) = &self.uad_ng_lists {
                // if let Some(app_entry) = uad_ng_lists.apps.get(&package.pkg) {
                //     format!("{}\n{}", package_name, app_entry.description)
                // } else {
                //     package_name
                // }
                package_name
            } else {
                package_name
            };

            // let system = if package.flags.contains("SYSTEM") { "Yes" } else { "No" };
            let is_system = package.flags.contains("SYSTEM");

            // Get app info data from ANY available cache (not filtered by renderer setting)
            // Renderer settings only control whether to START fetching, not displaying cached data
            let google_play_data = if !is_system {
                google_play_data_map.get(&package.pkg).cloned()
            } else {
                None
            };

            let debloat_category = if let Some(uad_ng_lists) = &self.uad_ng_lists {
                uad_ng_lists
                    .apps
                    .get(&package.pkg)
                    .map(|app| app.removal.clone())
                    .unwrap_or_else(|| "Unknown".to_string())
            } else {
                "Unknown".to_string()
            };

            // Get F-Droid data from prepared map (for non-system apps)
            let fdroid_data = if !is_system {
                fdroid_data_map.get(&package.pkg).cloned()
            } else {
                None
            };

            // Get APKMirror data from prepared map (for system apps)
            let apkmirror_data = if is_system {
                apkmirror_data_map.get(&package.pkg).cloned()
            } else {
                None
            };

            // Queue APKMirror upload if auto-upload is enabled and we have version info
            if self.apkmirror_auto_upload_enabled && is_system {
                if let Some((_, _, _, apkmirror_version)) = &apkmirror_data {
                    // Only queue if we haven't already processed this package
                    if self.get_upload_status(&package.pkg).is_none() {
                        if let Some(device_serial) = &self.selected_device {
                            self.queue_apkmirror_upload(
                                &package.pkg,
                                &package.versionName,
                                package.versionCode,
                                apkmirror_version.clone(),
                                &package.codePath,
                                device_serial,
                            );
                        }
                    }
                }
            }

            let runtime_perms = package
                .users
                .get(0)
                .map(|u| u.runtimePermissions.len())
                .unwrap_or(0)
                .to_string();
            let _installed = package
                .users
                .get(0)
                .map(|u| if u.installed { "Yes" } else { "No" })
                .unwrap_or("No");
            let enabled = package
                .users
                .get(0)
                .map(|u| Self::enabled_to_display_string(u.enabled, u.installed, is_system))
                .unwrap_or("DEFAULT");

            let install_reason_value = package.users.get(0).map(|u| u.installReason).unwrap_or(0);
            let install_reason_base = Self::install_reason_to_string(install_reason_value);
            let install_reason = if is_system {
                if install_reason_value == 0 {
                    "SYSTEM".to_string()
                } else {
                    format!("{} (SYSTEM)", install_reason_base)
                }
            } else {
                install_reason_base.to_string()
            };

            let clicked_idx_clone = clicked_package_idx.clone();
            let enabled_text = enabled.to_string();
            let package_name_for_buttons = package.pkg.clone();
            let _install_reason_str = install_reason.clone();
            let enabled_str = enabled.to_string();
            let debloat_category_text = debloat_category.clone();
            // Use installed version from self.installed_packages instead of crawled versions
            let installed_version = package.versionName.clone();
            // Renderer settings control whether to fetch new data (show spinner while loading)
            let google_play_fetching_enabled = self.google_play_renderer_enabled && !is_system;
            let fdroid_fetching_enabled = self.fdroid_renderer_enabled && !is_system;
            let apkmirror_fetching_enabled = self.apkmirror_renderer_enabled && is_system;
            let any_renderer_enabled = google_play_fetching_enabled
                || fdroid_fetching_enabled
                || apkmirror_fetching_enabled;
            // Check if all fetch sources failed for this package (show original name instead of spinner)
            let fetch_failed = fetch_failed_packages.contains(&package.pkg);

            // Extract Google Play data for display - clone into owned strings for the closure
            let (gp_texture_id, gp_title, gp_developer) =
                if let Some((texture_opt, title, developer, _version)) = &google_play_data {
                    let title_owned = title.clone();
                    let developer_owned = developer.clone();
                    (
                        texture_opt.as_ref().map(|t| t.id()),
                        Some(title_owned),
                        Some(developer_owned),
                    )
                } else {
                    (None, None, None)
                };

            // Extract F-Droid data for display - clone into owned strings for the closure
            let (fd_texture_id, fd_title, fd_developer) =
                if let Some((texture_opt, title, developer, _version)) = &fdroid_data {
                    let title_owned = title.clone();
                    let developer_owned = developer.clone();
                    (
                        texture_opt.as_ref().map(|t| t.id()),
                        Some(title_owned),
                        Some(developer_owned),
                    )
                } else {
                    (None, None, None)
                };

            // Extract APKMirror data for display - clone into owned strings for the closure
            let (am_texture_id, am_title, am_developer) =
                if let Some((texture_opt, title, developer, _version)) = &apkmirror_data {
                    let title_owned = title.clone();
                    let developer_owned = developer.clone();
                    (
                        texture_opt.as_ref().map(|t| t.id()),
                        Some(title_owned),
                        Some(developer_owned),
                    )
                } else {
                    (None, None, None)
                };

            debloat_table = debloat_table.row(|table_row| {
                // Display logic: show data from ANY available cache
                // Priority: F-Droid data first, then Google Play data
                // Renderer settings only control whether to START fetching (show spinner while loading)
                let installed_version_clone = installed_version.clone();
                let mut row_builder = if let (Some(title), Some(developer)) =
                    (fd_title.clone(), fd_developer.clone())
                {
                    // F-Droid data available - show it regardless of renderer setting
                    let title = title.clone();
                    let developer = developer.clone();
                    let version_str = installed_version_clone.clone();

                    table_row.widget_cell(move |ui: &mut egui::Ui| {
                        ui.horizontal(|ui| {
                            if let Some(tex_id) = fd_texture_id {
                                ui.image((tex_id, egui::vec2(38.0, 38.0))); // 48.0
                            }
                            ui.vertical(|ui| {
                                ui.style_mut().spacing.item_spacing.y = 0.1;
                                ui.label(egui::RichText::new(&title).strong());
                                ui.label(
                                    egui::RichText::new(&developer)
                                        .small()
                                        .color(egui::Color32::GRAY),
                                );
                                // ui.label(egui::RichText::new(format!("v{}", version_str)).small());
                            });
                        });
                    })
                } else if let (Some(title), Some(developer)) =
                    (gp_title.clone(), gp_developer.clone())
                {
                    // Google Play data available - show it regardless of renderer setting
                    let title = title.clone();
                    let developer = developer.clone();
                    let version_str = installed_version_clone.clone();

                    table_row.widget_cell(move |ui: &mut egui::Ui| {
                        ui.horizontal(|ui| {
                            if let Some(tex_id) = gp_texture_id {
                                ui.image((tex_id, egui::vec2(38.0, 38.0))); // 48.0
                            }
                            ui.vertical(|ui| {
                                ui.style_mut().spacing.item_spacing.y = 0.1;
                                ui.label(egui::RichText::new(&title).strong());
                                ui.label(
                                    egui::RichText::new(&developer)
                                        .small()
                                        .color(egui::Color32::GRAY),
                                );
                                // ui.label(egui::RichText::new(format!("v{}", version_str)).small());
                            });
                        });
                    })
                } else if let (Some(title), Some(developer)) =
                    (am_title.clone(), am_developer.clone())
                {
                    // APKMirror data available - show it regardless of renderer setting
                    let title = title.clone();
                    let developer = developer.clone();
                    let version_str = installed_version_clone.clone();

                    table_row.widget_cell(move |ui: &mut egui::Ui| {
                        ui.horizontal(|ui| {
                            if let Some(tex_id) = am_texture_id {
                                ui.image((tex_id, egui::vec2(38.0, 38.0))); //48.0
                            }
                            ui.vertical(|ui| {
                                ui.style_mut().spacing.item_spacing.y = 0.1;
                                ui.label(egui::RichText::new(&title).strong());
                                ui.label(
                                    egui::RichText::new(&developer)
                                        .small()
                                        .color(egui::Color32::GRAY),
                                );
                                // ui.label(egui::RichText::new(format!("v{}", version_str)).small());
                            });
                        });
                    })
                } else if any_renderer_enabled && !is_system {
                    // A renderer is enabled but no data available yet
                    if fetch_failed {
                        // All sources failed - show original package name (no spinner)
                        table_row.widget_cell(move |ui: &mut egui::Ui| {
                            ui.add(egui::Label::new(&package_name_with_desc).wrap());
                        })
                    } else {
                        // Still loading - show spinner
                        let pkg_name = package_name_with_desc.clone();
                        table_row.widget_cell(move |ui: &mut egui::Ui| {
                            ui.style_mut().spacing.item_spacing.y = 0.1;
                            ui.with_layout(
                                egui::Layout::left_to_right(egui::Align::Center)
                                    .with_main_wrap(true),
                                |ui| {
                                    ui.horizontal(|ui| {
                                        ui.spinner();
                                        ui.label(&pkg_name);
                                    });
                                },
                            );
                        })
                    }
                } else {
                    // No renderer enabled or system app - show plain package name
                    // table_row.cell(&package_name_with_desc)
                    table_row.widget_cell(move |ui: &mut egui::Ui| {
                        ui.add(egui::Label::new(&package_name_with_desc).wrap());
                    })
                };

                row_builder = row_builder
                    .widget_cell(move |ui: &mut egui::Ui| {
                        // Determine background color based on debloat category
                        let bg_color = match debloat_category_text.as_str() {
                            "Recommended" => egui::Color32::from_rgb(56, 142, 60), // Green
                            "Advanced" => egui::Color32::from_rgb(33, 150, 243),   // Blue
                            "Expert" => egui::Color32::from_rgb(255, 152, 0),      // Orange
                            "Unsafe" => egui::Color32::from_rgb(255, 235, 59),     // Yellow
                            "Unknown" => egui::Color32::from_rgb(255, 255, 255),   // White
                            _ => egui::Color32::from_rgb(158, 158, 158),           // Gray fallback
                        };

                        // Determine text color based on background (white needs dark text)
                        let text_color = match debloat_category_text.as_str() {
                            "Unknown" | "Unsafe" => egui::Color32::from_rgb(0, 0, 0), // Black text for white/yellow bg
                            _ => egui::Color32::WHITE, // White text for others
                        };

                        ui.horizontal(|ui| {
                            // Create a styled chip-like label
                            egui::Frame::new()
                                .fill(bg_color)
                                .corner_radius(8.0)
                                .inner_margin(egui::Margin::symmetric(12, 6))
                                .show(ui, |ui| {
                                    ui.label(
                                        egui::RichText::new(&debloat_category_text)
                                            .color(text_color)
                                            .size(12.0),
                                    );
                                });
                        });
                    })
                    .cell(&runtime_perms)
                    // .cell(system)
                    // .cell(installed)
                    .widget_cell(move |ui: &mut egui::Ui| {
                        // Determine background color based on enabled status
                        let bg_color = match enabled_text.as_str() {
                            "REMOVED_USER" => egui::Color32::from_rgb(211, 47, 47), // Red
                            "DISABLED" => egui::Color32::from_rgb(211, 47, 47),     // Red
                            "DISABLED_USER" => egui::Color32::from_rgb(211, 47, 47), // Red
                            "DEFAULT" => egui::Color32::from_rgb(56, 142, 60),      // Green
                            "ENABLED" => egui::Color32::from_rgb(56, 142, 60),      // Green
                            "UNKNOWN" => egui::Color32::from_rgb(56, 142, 60),      // Green
                            _ => egui::Color32::from_rgb(158, 158, 158),            // Gray fallback
                        };

                        ui.horizontal(|ui| {
                            // Create a styled chip-like label
                            let text_color = egui::Color32::WHITE;
                            egui::Frame::new()
                                .fill(bg_color)
                                .corner_radius(8.0)
                                .inner_margin(egui::Margin::symmetric(12, 6))
                                .show(ui, |ui| {
                                    ui.label(
                                        egui::RichText::new(&enabled_text)
                                            .color(text_color)
                                            .size(12.0),
                                    );
                                });
                        });
                    })
                    .cell(install_reason)
                    .widget_cell(move |ui: &mut egui::Ui| {
                        ui.horizontal(|ui| {
                            // Info button
                            let chip = assist_chip("").leading_icon_svg(INFO_SVG).elevated(true);
                            if ui
                                .add(chip.on_click(move || {
                                    tracing::info!("Opening package info dialog");
                                }))
                                .clicked()
                            {
                                // open package_details_window
                                if let Ok(mut clicked) = clicked_idx_clone.lock() {
                                    *clicked = Some(idx);
                                }
                            }

                            // Uninstall button - only show if install_reason is NOT SYSTEM
                            if enabled_str.contains("DEFAULT") || enabled_str.contains("ENABLED") {
                                let uninstall_chip =
                                    assist_chip("").leading_icon_svg(TRASH_RED_SVG).elevated(true);

                                let pkg_name_uninstall = package_name_for_buttons.clone();
                                if ui
                                    .add(uninstall_chip.on_click(move || {
                                        tracing::info!(
                                            "Uninstall clicked for: {}",
                                            pkg_name_uninstall
                                        );
                                    }))
                                    .clicked()
                                {
                                    // Signal that uninstall was clicked
                                    ui.data_mut(|data| {
                                        data.insert_temp(
                                            egui::Id::new("uninstall_clicked_package"),
                                            package_name_for_buttons.clone(),
                                        );
                                        data.insert_temp(
                                            egui::Id::new("uninstall_clicked_is_system"),
                                            is_system,
                                        );
                                    });
                                }
                            }

                            // Show Enable button
                            if enabled_str.contains("REMOVED_USER")
                                || enabled_str.contains("DISABLED_USER")
                                || enabled_str.contains("DISABLED")
                            {
                                let enable_chip =
                                    assist_chip("").leading_icon_svg(ENABLE_GREEN_SVG).elevated(true);

                                let pkg_name_enable = package_name_for_buttons.clone();
                                if ui
                                    .add(enable_chip.on_click(move || {
                                        tracing::info!("Enable clicked for: {}", pkg_name_enable);
                                    }))
                                    .clicked()
                                {
                                    // Signal that enable was clicked
                                    ui.data_mut(|data| {
                                        data.insert_temp(
                                            egui::Id::new("enable_clicked_package"),
                                            package_name_for_buttons.clone(),
                                        );
                                    });
                                }
                            }

                            // Show Disable button (for DEFAULT, ENABLED, UNKNOWN)
                            if enabled_str.contains("DEFAULT") || enabled_str.contains("ENABLED") {
                                let disable_chip =
                                    assist_chip("").leading_icon_svg(DISABLE_RED_SVG).elevated(true);

                                let pkg_name_disable = package_name_for_buttons.clone();
                                if ui
                                    .add(disable_chip.on_click(move || {
                                        tracing::info!("Disable clicked for: {}", pkg_name_disable);
                                    }))
                                    .clicked()
                                {
                                    // Signal that disable was clicked
                                    ui.data_mut(|data| {
                                        data.insert_temp(
                                            egui::Id::new("disable_clicked_package"),
                                            package_name_for_buttons.clone(),
                                        );
                                    });
                                }
                            }
                        });
                    })
                    .id(format!("debloat_table_row_{}", idx));

                if is_selected {
                    row_builder = row_builder.selected(true);
                }

                row_builder
            });
        }

        // Show the table and get the selection state back
        let table_response = debloat_table.show(ui);

        // CRITICAL: Sync sort state from table response to our data
        // The table widget persists sort state and may have a different sort than we expect
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

        // Sync table selection state back to our internal state
        // Map the filtered row selection back to package names
        if table_response.selected_rows.len() == filtered_package_names.len() {
            for (filtered_idx, package_name) in filtered_package_names.iter().enumerate() {
                if let Some(&selected) = table_response.selected_rows.get(filtered_idx) {
                    if selected {
                        self.selected_packages.insert(package_name.clone());
                    } else {
                        self.selected_packages.remove(package_name);
                    }
                }
            }
        }

        // Handle package name click
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
        let mut batch_uninstall: bool = false;
        let mut batch_disable: bool = false;
        let mut batch_enable: bool = false;

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
            if data
                .get_temp::<bool>(egui::Id::new("batch_uninstall_clicked"))
                .unwrap_or(false)
            {
                batch_uninstall = true;
                data.remove::<bool>(egui::Id::new("batch_uninstall_clicked"));
            }
            if data
                .get_temp::<bool>(egui::Id::new("batch_disable_clicked"))
                .unwrap_or(false)
            {
                batch_disable = true;
                data.remove::<bool>(egui::Id::new("batch_disable_clicked"));
            }
            if data
                .get_temp::<bool>(egui::Id::new("batch_enable_clicked"))
                .unwrap_or(false)
            {
                batch_enable = true;
                data.remove::<bool>(egui::Id::new("batch_enable_clicked"));
            }
        });

        // Perform uninstall if clicked
        if let Some(pkg_name) = uninstall_package {
            if let Some(ref device) = self.selected_device {
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
                                self.selected_packages.remove(&pkg_name);
                            }

                            result = Some(AdbResult::Success(pkg_name.clone()));
                        }
                        Err(e) => {
                            tracing::error!("Failed to uninstall app({}): {}", pkg_name, e);
                            result = Some(AdbResult::Failure);
                        }
                    }
                }
            } else {
                tracing::error!("No device selected for uninstall");
                result = Some(AdbResult::Failure);
            }
        }

        // Perform enable if clicked
        if let Some(pkg_name) = enable_package {
            if let Some(ref device) = self.selected_device {
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

                            result = Some(AdbResult::Success(pkg_name.clone()));
                        }
                        Err(e) => {
                            tracing::error!("Failed to enable app: {}", e);
                            result = Some(AdbResult::Failure);
                        }
                    }
                }
            } else {
                tracing::error!("No device selected for enable");
                result = Some(AdbResult::Failure);
            }
        }

        // Perform disable if clicked
        if let Some(pkg_name) = disable_package {
            if let Some(ref device) = self.selected_device {
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

                            result = Some(AdbResult::Success(pkg_name.clone()));
                        }
                        Err(e) => {
                            tracing::error!("Failed to disable app: {}", e);
                            result = Some(AdbResult::Failure);
                        }
                    }
                }
            } else {
                tracing::error!("No device selected for disable");
                result = Some(AdbResult::Failure);
            }
        }

        // Handle batch uninstall
        if batch_uninstall {
            if let Some(ref device) = self.selected_device {
                {
                    let packages_to_uninstall: Vec<String> =
                        self.selected_packages.iter().cloned().collect();
                    for pkg_name in packages_to_uninstall {
                        // Determine if package is system
                        let is_system = self
                            .installed_packages
                            .iter()
                            .find(|p| p.pkg == pkg_name)
                            .map(|p| p.flags.contains("SYSTEM"))
                            .unwrap_or(false);

                        let uninstall_result = if is_system {
                            crate::adb::uninstall_app_user(&pkg_name, device, None)
                        } else {
                            crate::adb::uninstall_app(&pkg_name, device)
                        };

                        match uninstall_result {
                            Ok(output) => {
                                tracing::info!("App uninstalled successfully: {}", output);

                                tracing::info!("Package removed: {}", pkg_name);

                                if is_system {
                                    // For system apps, just mark as uninstalled/removed for current user
                                    if let Some(pkg) = self
                                        .installed_packages
                                        .iter_mut()
                                        .find(|p| p.pkg == pkg_name)
                                    {
                                        for user in pkg.users.iter_mut() {
                                            user.installed = false;
                                            user.enabled = 0; // Reset
                                        }
                                    }
                                } else {
                                    // For user apps, remove from list
                                    self.installed_packages.retain(|pkg| pkg.pkg != pkg_name);
                                    self.selected_packages.remove(&pkg_name);
                                }

                                result = Some(AdbResult::Success(pkg_name.clone()));
                            }
                            Err(e) => {
                                tracing::error!("Failed to uninstall app {}: {}", pkg_name, e);
                                result = Some(AdbResult::Failure);
                            }
                        }
                    }
                }
            } else {
                tracing::error!("No device selected for batch uninstall");
                result = Some(AdbResult::Failure);
            }
        }

        // Handle batch disable
        if batch_disable {
            if let Some(ref device) = self.selected_device {
                {
                    let packages_to_disable: Vec<String> =
                        self.selected_packages.iter().cloned().collect();
                    for pkg_name in packages_to_disable {
                        match crate::adb::disable_app_current_user(&pkg_name, device, None) {
                            Ok(output) => {
                                tracing::info!("App disabled successfully: {}", output);

                                tracing::info!("Package disabled in batch: {}", pkg_name);

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

                                result = Some(AdbResult::Success(pkg_name.clone()));
                            }
                            Err(e) => {
                                tracing::error!("Failed to disable app {}: {}", pkg_name, e);
                                result = Some(AdbResult::Failure);
                            }
                        }
                    }
                }
            } else {
                tracing::error!("No device selected for batch disable");
                result = Some(AdbResult::Failure);
            }
        }

        // Handle batch enable
        if batch_enable {
            if let Some(ref device) = self.selected_device {
                {
                    let packages_to_enable: Vec<String> =
                        self.selected_packages.iter().cloned().collect();
                    for pkg_name in packages_to_enable {
                        match crate::adb::enable_app(&pkg_name, device) {
                            Ok(output) => {
                                tracing::info!("App enabled successfully: {}", output);

                                tracing::info!("Package enabled in batch: {}", pkg_name);

                                // Update package state
                                if let Some(pkg) = self
                                    .installed_packages
                                    .iter_mut()
                                    .find(|p| p.pkg == pkg_name)
                                {
                                    for user in pkg.users.iter_mut() {
                                        user.enabled = 1; // ENABLED
                                        user.installed = true;
                                    }
                                }

                                result = Some(AdbResult::Success(pkg_name.clone()));
                            }
                            Err(e) => {
                                tracing::error!("Failed to enable app {}: {}", pkg_name, e);
                                result = Some(AdbResult::Failure);
                            }
                        }
                    }
                }
            } else {
                tracing::error!("No device selected for batch enable");
                result = Some(AdbResult::Failure);
            }
        }

        // Show package details dialog
        self.package_details_dialog
            .show(ui.ctx(), &self.installed_packages, &self.uad_ng_lists);

        result
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
