use crate::db::establish_connection;
use crate::models::{NewPackageInfoCache, PackageInfoCache};
use crate::schema::package_info_cache;
use diesel::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};

/// Get cached package info by package ID and device serial
pub fn get_cached_package_info(pkg_id: &str, device_serial: &str) -> Option<PackageInfoCache> {
    let mut conn = establish_connection();

    package_info_cache::table
        .filter(package_info_cache::pkg_id.eq(pkg_id))
        .filter(package_info_cache::device_serial.eq(device_serial))
        .order(package_info_cache::updated_at.desc())
        .first::<PackageInfoCache>(&mut conn)
        .ok()
}

/// Get cached package info by checksum and device serial (to check if package changed)
pub fn get_cached_package_info_by_checksum(
    pkg_checksum: &str,
    device_serial: &str,
) -> Option<PackageInfoCache> {
    let mut conn = establish_connection();

    package_info_cache::table
        .filter(package_info_cache::pkg_checksum.eq(pkg_checksum))
        .filter(package_info_cache::device_serial.eq(device_serial))
        .order(package_info_cache::updated_at.desc())
        .first::<PackageInfoCache>(&mut conn)
        .ok()
}

/// Insert or update package info cache
pub fn upsert_package_info_cache(
    pkg_id: &str,
    pkg_checksum: &str,
    dump_text: &str,
    code_path: &str,
    version_code: i32,
    version_name: &str,
    first_install_time: &str,
    last_update_time: &str,
    apk_path: Option<&str>,
    apk_sha256sum: Option<&str>,
    izzyscore: Option<i32>,
    device_serial: &str,
) -> Result<PackageInfoCache, diesel::result::Error> {
    let mut conn = establish_connection();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i32;

    // Check if entry exists
    let existing = get_cached_package_info(pkg_id, device_serial);

    if let Some(existing_cache) = existing {
        // Update existing entry
        diesel::update(package_info_cache::table.find(existing_cache.id))
            .set((
                package_info_cache::pkg_checksum.eq(pkg_checksum),
                package_info_cache::dump_text.eq(dump_text),
                package_info_cache::code_path.eq(code_path),
                package_info_cache::version_code.eq(version_code),
                package_info_cache::version_name.eq(version_name),
                package_info_cache::first_install_time.eq(first_install_time),
                package_info_cache::last_update_time.eq(last_update_time),
                package_info_cache::apk_path.eq(apk_path),
                package_info_cache::apk_sha256sum.eq(apk_sha256sum),
                package_info_cache::izzyscore.eq(izzyscore.or(existing_cache.izzyscore)),
                package_info_cache::updated_at.eq(now),
            ))
            .execute(&mut conn)?;

        package_info_cache::table
            .find(existing_cache.id)
            .first::<PackageInfoCache>(&mut conn)
    } else {
        // Insert new entry
        let new_cache = NewPackageInfoCache {
            pkg_id,
            pkg_checksum,
            dump_text,
            code_path,
            version_code,
            version_name,
            first_install_time,
            last_update_time,
            apk_path,
            apk_sha256sum,
            izzyscore,
            device_serial,
            created_at: now,
            updated_at: now,
        };

        diesel::insert_into(package_info_cache::table)
            .values(&new_cache)
            .execute(&mut conn)?;

        package_info_cache::table
            .order(package_info_cache::id.desc())
            .first::<PackageInfoCache>(&mut conn)
    }
}

/// Update APK path and SHA256 for a cached package
pub fn update_package_apk_info(
    cache_id: i32,
    apk_path: &str,
    apk_sha256sum: &str,
) -> Result<(), diesel::result::Error> {
    let mut conn = establish_connection();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i32;

    diesel::update(package_info_cache::table.find(cache_id))
        .set((
            package_info_cache::apk_path.eq(apk_path),
            package_info_cache::apk_sha256sum.eq(apk_sha256sum),
            package_info_cache::updated_at.eq(now),
        ))
        .execute(&mut conn)?;

    Ok(())
}

/// Get all cached packages for a device that have apk_path set
pub fn get_cached_packages_with_apk(device_serial: &str) -> Vec<PackageInfoCache> {
    let mut conn = establish_connection();

    package_info_cache::table
        .filter(package_info_cache::device_serial.eq(device_serial))
        .filter(package_info_cache::apk_path.is_not_null())
        .load::<PackageInfoCache>(&mut conn)
        .unwrap_or_default()
}

/// Get all cached packages for a device that don't have apk_path set
pub fn get_cached_packages_without_apk(device_serial: &str) -> Vec<PackageInfoCache> {
    let mut conn = establish_connection();

    package_info_cache::table
        .filter(package_info_cache::device_serial.eq(device_serial))
        .filter(package_info_cache::apk_path.is_null())
        .load::<PackageInfoCache>(&mut conn)
        .unwrap_or_default()
}

/// Update IzzyRisk score for a cached package
pub fn update_package_izzyscore(
    cache_id: i32,
    izzyscore: i32,
) -> Result<(), diesel::result::Error> {
    let mut conn = establish_connection();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i32;

    diesel::update(package_info_cache::table.find(cache_id))
        .set((
            package_info_cache::izzyscore.eq(Some(izzyscore)),
            package_info_cache::updated_at.eq(now),
        ))
        .execute(&mut conn)?;

    Ok(())
}

/// Get all cached packages for a device
pub fn get_all_cached_packages(device_serial: &str) -> Vec<PackageInfoCache> {
    let mut conn = establish_connection();

    package_info_cache::table
        .filter(package_info_cache::device_serial.eq(device_serial))
        .load::<PackageInfoCache>(&mut conn)
        .unwrap_or_default()
}

/// Delete cache entries for packages that no longer exist
pub fn cleanup_stale_cache(
    device_serial: &str,
    current_pkg_ids: &[String],
) -> Result<usize, diesel::result::Error> {
    let mut conn = establish_connection();

    diesel::delete(
        package_info_cache::table
            .filter(package_info_cache::device_serial.eq(device_serial))
            .filter(package_info_cache::pkg_id.ne_all(current_pkg_ids)),
    )
    .execute(&mut conn)
}
