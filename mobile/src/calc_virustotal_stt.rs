use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Status of a VirusTotal scan for a file
#[derive(Debug, Clone)]
pub enum FileScanStatus {
    Pending,
    Scanning,
    Uploading,
    WaitingForAnalysis {
        uploaded_at: Instant,
        analysis_id: String,
    },
    Completed(FileScanResult),
    Error(String),
}

/// Result of a VirusTotal scan for a single file
#[derive(Debug, Clone)]
pub struct FileScanResult {
    pub file_path: String,
    pub sha256: String,
    pub malicious: i32,
    pub suspicious: i32,
    pub undetected: i32,
    pub harmless: i32,
    pub dex_count: Option<i32>,
    pub reputation: i32,
    pub vt_link: String,
    /// True if the file was not found in VirusTotal (404 response)
    pub not_found: bool,
    /// True if the file was skipped (not an APK or SO file)
    pub skipped: bool,
    /// Error message if scanning failed for this specific file
    pub error: Option<String>,
}

/// Status of a VirusTotal scan for a package (may contain multiple files)
#[derive(Debug, Clone)]
pub enum ScanStatus {
    Pending,
    Scanning {
        scanned: usize,
        total: usize,
        operation: String,
    },
    Completed(CalcVirustotal),
    Error(String),
}

/// Result of a VirusTotal scan for a package (may contain multiple files)
#[derive(Debug, Clone)]
pub struct CalcVirustotal {
    pub file_results: Vec<FileScanResult>,
    /// Number of files that were attempted to scan
    pub files_attempted: usize,
    /// Number of files skipped due to invalid SHA256 hash
    pub files_skipped_invalid_hash: usize,
}

impl Default for CalcVirustotal {
    fn default() -> Self {
        Self {
            file_results: Vec::new(),
            files_attempted: 0,
            files_skipped_invalid_hash: 0,
        }
    }
}

/// Shared state for VirusTotal scanning
pub type ScannerState = Arc<Mutex<HashMap<String, ScanStatus>>>;

/// Shared rate limiter for VirusTotal API
pub type SharedRateLimiter = Arc<Mutex<RateLimiter>>;

/// Rate limiter for VirusTotal API (4 requests per minute with 5 seconds minimum interval)
pub struct RateLimiter {
    pub request_times: Vec<Instant>,
    pub max_requests: usize,
    pub time_window: Duration,
    pub min_interval: Duration,
    /// When a 429 is received, all threads should wait until this time
    pub rate_limit_until: Option<Instant>,
}
