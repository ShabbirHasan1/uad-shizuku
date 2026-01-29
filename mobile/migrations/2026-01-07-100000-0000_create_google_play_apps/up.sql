-- Create google_play_apps table
CREATE TABLE google_play_apps (
    id INTEGER PRIMARY KEY NOT NULL,
    package_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    developer TEXT NOT NULL,
    version TEXT,
    icon_base64 TEXT,
    score REAL,
    installs TEXT,
    updated INTEGER,
    raw_response TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX idx_google_play_apps_package_id ON google_play_apps(package_id);
CREATE INDEX idx_google_play_apps_updated_at ON google_play_apps(updated_at);
