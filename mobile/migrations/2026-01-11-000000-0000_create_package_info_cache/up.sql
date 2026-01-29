CREATE TABLE package_info_cache (
    id INTEGER PRIMARY KEY NOT NULL,
    pkg_id TEXT NOT NULL,
    pkg_checksum TEXT NOT NULL UNIQUE,
    dump_text TEXT NOT NULL,
    code_path TEXT NOT NULL,
    version_code INTEGER NOT NULL,
    version_name TEXT NOT NULL,
    first_install_time TEXT NOT NULL,
    last_update_time TEXT NOT NULL,
    apk_path TEXT,
    apk_sha256sum TEXT,
    device_serial TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Create an index on pkg_id and device_serial for faster lookups
CREATE INDEX idx_package_info_cache_pkg_device ON package_info_cache(pkg_id, device_serial);
