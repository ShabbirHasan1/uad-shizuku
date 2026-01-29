use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Status of a Hybrid Analysis scan for a file
#[derive(Debug, Clone)]
pub enum FileScanStatus {
    Pending,
    Scanning,
    Uploading,
    WaitingForAnalysis {
        uploaded_at: Instant,
        scan_id: String,
    },
    Completed(FileScanResult),
    Error(String),
}

/// Result of a Hybrid Analysis scan for a single file
#[derive(Debug, Clone)]
pub struct FileScanResult {
    pub file_path: String,
    pub sha256: String,
    pub verdict: String,
    pub threat_score: Option<i32>,
    pub threat_level: Option<i32>,
    pub classification_tags: Vec<String>,
    pub total_signatures: Option<i32>,
    pub ha_link: String,
    /// For rate-limited or waiting states, when to retry (as Unix timestamp in seconds)
    pub wait_until: Option<u64>,
    /// For pending analysis jobs, the job_id to check status later
    pub job_id: Option<String>,
    /// For error states, additional error details
    pub error_message: Option<String>,
}

/// Status of a Hybrid Analysis scan for a package (may contain multiple files)
#[derive(Debug, Clone)]
pub enum ScanStatus {
    Pending,
    Scanning {
        scanned: usize,
        total: usize,
        operation: String,
    },
    Completed(CalcHybridAnalysis),
    Error(String),
}

/// Result of a Hybrid Analysis scan for a package (may contain multiple files)
#[derive(Debug, Clone)]
pub struct CalcHybridAnalysis {
    pub file_results: Vec<FileScanResult>,
}

impl Default for CalcHybridAnalysis {
    fn default() -> Self {
        Self {
            file_results: Vec::new(),
        }
    }
}

/// Shared state for Hybrid Analysis scanning
pub type ScannerState = Arc<Mutex<HashMap<String, ScanStatus>>>;

/// Shared rate limiter for Hybrid Analysis API
pub type SharedRateLimiter = Arc<Mutex<RateLimiter>>;

/// Rate limiter for Hybrid Analysis API (3 seconds minimum interval between requests)
pub struct RateLimiter {
    pub last_request: Option<Instant>,
    pub min_interval: Duration,
    /// When a 429 is received for search/report requests, wait until this time
    pub rate_limit_until: Option<Instant>,
    /// When a 429 is received for upload requests, wait 1 hour
    pub upload_rate_limit_until: Option<Instant>,
    /// Track requests in the last minute for 5 requests/minute limit
    pub requests_last_minute: Vec<Instant>,
    /// Track requests in the last hour for 200 requests/hour limit
    pub requests_last_hour: Vec<Instant>,
}
