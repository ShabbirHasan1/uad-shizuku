#[derive(Debug, Clone)]
pub struct PackageDetailsDialog {
    pub open: bool,
    pub selected_package_index: Option<usize>,
}

impl Default for PackageDetailsDialog {
    fn default() -> Self {
        Self {
            open: false,
            selected_package_index: None,
        }
    }
}
