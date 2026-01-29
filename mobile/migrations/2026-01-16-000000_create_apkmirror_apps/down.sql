-- Drop apkmirror_apps table
DROP INDEX IF EXISTS idx_apkmirror_apps_updated_at;
DROP INDEX IF EXISTS idx_apkmirror_apps_package_id;
DROP TABLE IF EXISTS apkmirror_apps;
