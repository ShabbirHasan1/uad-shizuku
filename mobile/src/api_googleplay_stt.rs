#[derive(Debug, Clone)]
pub struct GooglePlayAppInfo {
    pub package_id: String,
    pub title: String,
    pub developer: String,
    pub version: Option<String>,
    pub icon_base64: Option<String>,
    pub score: Option<f32>,
    pub installs: Option<String>,
    pub updated: Option<i32>,
    pub raw_response: String,
}
