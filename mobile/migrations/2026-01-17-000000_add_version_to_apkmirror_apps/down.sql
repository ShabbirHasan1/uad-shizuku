-- Remove version column from apkmirror_apps table
-- SQLite doesn't support DROP COLUMN directly, so we need to recreate the table
CREATE TABLE apkmirror_apps_backup (
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

INSERT INTO apkmirror_apps_backup SELECT id, package_id, title, developer, icon_url, icon_base64, raw_response, created_at, updated_at FROM apkmirror_apps;

DROP TABLE apkmirror_apps;

ALTER TABLE apkmirror_apps_backup RENAME TO apkmirror_apps;

CREATE INDEX idx_apkmirror_apps_package_id ON apkmirror_apps(package_id);
CREATE INDEX idx_apkmirror_apps_updated_at ON apkmirror_apps(updated_at);
