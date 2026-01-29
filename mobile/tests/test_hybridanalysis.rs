use std::path::Path;
use uad_shizuku::api_hybridanalysis;

#[test]
#[ignore] // Requires API key - run with: cargo test test_ha_upload -- --ignored
fn test_ha_upload() {
    // Initialize tracing for debugging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Get API key from environment
    let api_key = std::env::var("HYBRID_ANALYSIS_API_KEY")
        .expect("HYBRID_ANALYSIS_API_KEY environment variable must be set");

    // Use a small test APK file
    let test_file =
        std::env::var("TEST_APK_PATH").expect("TEST_APK_PATH environment variable must be set");
    let file_path = Path::new(&test_file);

    assert!(
        file_path.exists(),
        "Test file does not exist: {}",
        test_file
    );

    // Test upload
    match api_hybridanalysis::ha_submit_file(file_path, &api_key) {
        Ok(response) => {
            println!("Upload successful!");
            println!("Job ID: {}", response.job_id);
            println!("Submission ID: {}", response.submission_id);
            println!("SHA256: {}", response.sha256);
        }
        Err(e) => {
            panic!("Upload failed: {}", e);
        }
    }
}

#[test]
#[ignore] // Requires API key - run with: cargo test test_ha_search_hash -- --ignored
fn test_ha_search_hash() {
    // Get API key from environment
    let api_key = std::env::var("HYBRID_ANALYSIS_API_KEY")
        .expect("HYBRID_ANALYSIS_API_KEY environment variable must be set");

    // Test with a known hash (Google Play Services)
    let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    match api_hybridanalysis::search_hash(sha256, &api_key) {
        Ok(response) => {
            println!("Search successful!");
            println!("Found {} reports", response.reports.len());
        }
        Err(api_hybridanalysis::HaError::NotFound) => {
            println!("Hash not found (expected for empty file hash)");
        }
        Err(e) => {
            panic!("Search failed: {}", e);
        }
    }
}

#[test]
#[ignore] // Requires API key - run with: cargo test test_ha_quota -- --ignored
fn test_ha_quota() {
    // Get API key from environment
    let api_key = std::env::var("HYBRID_ANALYSIS_API_KEY")
        .expect("HYBRID_ANALYSIS_API_KEY environment variable must be set");

    match api_hybridanalysis::check_quota(&api_key) {
        Ok(response) => {
            println!("Quota check successful!");
            println!("Response: {:?}", response);
        }
        Err(e) => {
            panic!("Quota check failed: {}", e);
        }
    }
}
