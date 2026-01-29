use serde::{Deserialize, Serialize};

/// VirusTotal API response for file reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalResponse {
    pub data: VirusTotalData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalData {
    pub id: String,
    #[serde(rename = "type")]
    pub data_type: String,
    pub attributes: VirusTotalAttributes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalAttributes {
    /// Last analysis date - may be missing if file hasn't been analyzed yet
    #[serde(default)]
    pub last_analysis_date: Option<i64>,
    /// Analysis stats - may be missing if file hasn't been analyzed yet
    #[serde(default)]
    pub last_analysis_stats: Option<LastAnalysisStats>,
    #[serde(default)]
    pub reputation: i32,
    #[serde(default)]
    pub androguard: Option<AndroidGuard>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastAnalysisStats {
    pub malicious: i32,
    pub suspicious: i32,
    pub undetected: i32,
    pub harmless: i32,
    pub timeout: i32,
    #[serde(rename = "confirmed-timeout")]
    pub confirmed_timeout: i32,
    pub failure: i32,
    #[serde(rename = "type-unsupported")]
    pub type_unsupported: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidGuard {
    #[serde(rename = "RiskIndicator")]
    pub risk_indicator: Option<RiskIndicator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskIndicator {
    #[serde(rename = "APK")]
    pub apk: Option<ApkInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkInfo {
    #[serde(rename = "DEX")]
    pub dex: Option<i32>,
}

/// VirusTotal API response for file upload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalUploadResponse {
    pub data: VirusTotalUploadData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalUploadData {
    pub id: String,
    #[serde(rename = "type")]
    pub data_type: String,
}

/// VirusTotal API response for getting large file upload URL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalUploadUrlResponse {
    pub data: String,
}
