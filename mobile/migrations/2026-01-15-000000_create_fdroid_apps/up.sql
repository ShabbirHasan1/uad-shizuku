-- Create fdroid_apps table
CREATE TABLE fdroid_apps (
    id INTEGER PRIMARY KEY NOT NULL,
    package_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    developer TEXT NOT NULL,
    version TEXT,
    icon_base64 TEXT,
    description TEXT,
    license TEXT,
    updated INTEGER,
    raw_response TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX idx_fdroid_apps_package_id ON fdroid_apps(package_id);
CREATE INDEX idx_fdroid_apps_updated_at ON fdroid_apps(updated_at);
