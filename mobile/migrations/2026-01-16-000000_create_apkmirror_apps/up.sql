-- Create apkmirror_apps table
CREATE TABLE apkmirror_apps (
    id INTEGER PRIMARY KEY NOT NULL,
    package_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    developer TEXT NOT NULL,
    icon_url TEXT,
    icon_base64 TEXT,
    raw_response TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX idx_apkmirror_apps_package_id ON apkmirror_apps(package_id);
CREATE INDEX idx_apkmirror_apps_updated_at ON apkmirror_apps(updated_at);
