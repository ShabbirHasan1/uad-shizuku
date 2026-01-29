use uad_shizuku::api_fdroid::fetch_app_details;

fn main() {
    let pkg = "org.fossify.gallery";
    match fetch_app_details(pkg) {
        Ok(info) => {
            println!("Successfully fetched F-Droid data:");
            println!("Package ID: {}", info.package_id);
            println!("Title: {}", info.title);
            println!("Developer: {}", info.developer);
            println!("Version: {:?}", info.version);
            println!("License: {:?}", info.license);
            println!("Updated: {:?}", info.updated);
        }
        Err(e) => {
            eprintln!("Error fetching data: {:?}", e);
        }
    }
}
