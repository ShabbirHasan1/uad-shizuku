use serde::{Deserialize, Deserializer, Serialize};

/// Helper function to deserialize null as empty string
fn deserialize_null_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

/// Hybrid Analysis API response for hash search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridAnalysisHashResponse {
    pub sha256s: Vec<String>,
    #[serde(default)]
    pub reports: Vec<HybridAnalysisReportInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridAnalysisReportInfo {
    #[serde(default, deserialize_with = "deserialize_null_string")]
    pub id: String,
    #[serde(default)]
    pub environment_id: i32,
    #[serde(default)]
    pub environment_description: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error_type: Option<String>,
    #[serde(default)]
    pub error_origin: Option<String>,
    #[serde(default)]
    pub verdict: Option<String>,
}

/// Hybrid Analysis API response for report summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridAnalysisReportResponse {
    #[serde(default)]
    pub classification_tags: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub submissions: Vec<HybridAnalysisSubmission>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_null_string")]
    pub job_id: String,
    #[serde(default)]
    pub environment_id: i32,
    #[serde(default, deserialize_with = "deserialize_null_string")]
    pub environment_description: String,
    #[serde(default, deserialize_with = "deserialize_null_string")]
    pub state: String,
    #[serde(default)]
    pub error_type: Option<String>,
    #[serde(default)]
    pub error_origin: Option<String>,
    #[serde(default, deserialize_with = "deserialize_null_string")]
    pub submit_name: String,
    #[serde(default, deserialize_with = "deserialize_null_string")]
    pub md5: String,
    #[serde(default, deserialize_with = "deserialize_null_string")]
    pub sha1: String,
    #[serde(default, deserialize_with = "deserialize_null_string")]
    pub sha256: String,
    #[serde(default)]
    pub sha512: Option<String>,
    #[serde(default)]
    pub threat_score: Option<i32>,
    #[serde(default)]
    pub threat_level: Option<i32>,
    #[serde(default, deserialize_with = "deserialize_null_string")]
    pub verdict: String,
    #[serde(default)]
    pub total_network_connections: Option<i32>,
    #[serde(default)]
    pub total_processes: Option<i32>,
    #[serde(default)]
    pub total_signatures: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridAnalysisSubmission {
    #[serde(default)]
    pub submission_id: Option<String>,
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

/// Hybrid Analysis API response for file submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridAnalysisQuickScanResponse {
    pub job_id: String,
    pub submission_id: String,
    pub environment_id: i32,
    pub sha256: String,
}

/// Hybrid Analysis API response for job state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridAnalysisJobStateResponse {
    #[serde(default, deserialize_with = "deserialize_null_string")]
    pub state: String,
    #[serde(default)]
    pub error_type: Option<String>,
    #[serde(default)]
    pub error_origin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridAnalysisScanner {
    pub name: String,
    pub status: String,
    pub status_raw: String,
    #[serde(default)]
    pub error_message: Option<String>,
    pub progress: i32,
    #[serde(default)]
    pub total: Option<i32>,
    #[serde(default)]
    pub positives: Option<i32>,
    #[serde(default)]
    pub percent: Option<f64>,
    #[serde(default)]
    pub anti_virus_results: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridAnalysisScannersV2 {
    #[serde(default)]
    pub crowdstrike_ml: Option<HybridAnalysisScanner>,
    #[serde(default)]
    pub metadefender: Option<HybridAnalysisScanner>,
    #[serde(default)]
    pub virustotal: Option<HybridAnalysisScanner>,
}

/// Hybrid Analysis API response for submission quota
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridAnalysisQuotaResponse {
    #[serde(default)]
    pub detonation: Option<HybridAnalysisQuotaDetonation>,
    #[serde(default)]
    pub quick_scan: Option<HybridAnalysisQuotaDetonation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridAnalysisQuotaDetonation {
    #[serde(default)]
    pub apikey: Option<HybridAnalysisQuotaInfo>,
    #[serde(default)]
    pub quota_reached: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridAnalysisQuotaInfo {
    #[serde(default)]
    pub quota: Option<HybridAnalysisQuotaValues>,
    #[serde(default)]
    pub used: Option<HybridAnalysisQuotaValues>,
    #[serde(default)]
    pub available: Option<HybridAnalysisQuotaValues>,
    #[serde(default)]
    pub quota_reached: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridAnalysisQuotaValues {
    #[serde(default)]
    pub hour: Option<i32>,
    #[serde(default)]
    pub day: Option<i32>,
    #[serde(default)]
    pub week: Option<i32>,
    #[serde(default)]
    pub month: Option<i32>,
    #[serde(default)]
    pub year: Option<i32>,
    #[serde(default)]
    pub omega: Option<i32>,
}
