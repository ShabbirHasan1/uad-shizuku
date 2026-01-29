use crate::models::ApkMirrorApp;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub enum ApkMirrorFetchStatus {
    Pending,
    Fetching,
    Success(ApkMirrorApp),
    Error(String),
}

pub struct ApkMirrorQueue {
    pub queue: Arc<Mutex<VecDeque<String>>>,
    pub results: Arc<Mutex<HashMap<String, ApkMirrorFetchStatus>>>,
    pub is_running: Arc<Mutex<bool>>,
    pub email: Arc<Mutex<String>>,
}

/// Status for APKMirror upload operations
#[derive(Debug, Clone)]
pub enum ApkMirrorUploadStatus {
    /// Waiting to be processed
    Pending,
    /// Computing MD5 hash for uploadability check
    ComputingHash,
    /// Checking if APK is uploadable (doesn't exist on APKMirror)
    CheckingUploadable,
    /// Pulling APK file from device
    PullingApk,
    /// Uploading APK to APKMirror
    Uploading,
    /// Upload completed successfully
    Success(String), // message
    /// APK already exists on APKMirror
    AlreadyExists,
    /// APKMirror version is same or newer (no upload needed)
    VersionNotNewer,
    /// Upload failed with error
    Error(String),
    /// Skipped (not uploadable for some reason)
    Skipped(String),
    /// Rate limited by APKMirror (too many uploads in 24 hours)
    RateLimited,
}

/// Item in the upload queue
#[derive(Debug, Clone)]
pub struct ApkMirrorUploadItem {
    pub package_id: String,
    pub device_version_name: String,
    pub device_version_code: i32,
    pub apkmirror_version: Option<String>,
    pub apk_path: String,
    pub device_serial: String,
}

/// Queue for managing APKMirror uploads
pub struct ApkMirrorUploadQueue {
    pub queue: Arc<Mutex<VecDeque<ApkMirrorUploadItem>>>,
    pub results: Arc<Mutex<HashMap<String, ApkMirrorUploadStatus>>>,
    pub is_running: Arc<Mutex<bool>>,
    pub email: Arc<Mutex<String>>,
    pub name: Arc<Mutex<String>>,
    pub tmp_dir: Arc<Mutex<String>>,
    /// Timestamp when rate limit expires (None if not rate limited)
    pub rate_limit_until: Arc<Mutex<Option<std::time::Instant>>>,
}
