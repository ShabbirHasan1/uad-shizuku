#[derive(Debug, Clone)]
pub struct ApkMirrorAppInfo {
    pub package_id: String,
    pub title: String,
    pub developer: String,
    pub version: Option<String>,
    pub icon_url: Option<String>,
    pub icon_base64: Option<String>,
    pub raw_response: String,
}

#[derive(Debug, Clone)]
pub struct ApkMirrorUploadResult {
    pub success: bool,
    pub already_exists: bool,
    pub rate_limited: bool,
    pub message: String,
}
