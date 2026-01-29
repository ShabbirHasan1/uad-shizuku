#[derive(Debug, Clone)]
pub struct FDroidAppInfo {
    pub package_id: String,
    pub title: String,
    pub developer: String,
    pub version: Option<String>,
    pub icon_base64: Option<String>,
    pub description: Option<String>,
    pub license: Option<String>,
    pub updated: Option<i32>,
    pub raw_response: String,
}
