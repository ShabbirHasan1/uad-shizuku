-- Your SQL goes here
CREATE TABLE posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  published BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE virustotal_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  package_name TEXT NOT NULL,
  file_path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  last_analysis_date INTEGER NOT NULL,
  malicious INTEGER NOT NULL,
  suspicious INTEGER NOT NULL,
  undetected INTEGER NOT NULL,
  harmless INTEGER NOT NULL,
  timeout INTEGER NOT NULL,
  failure INTEGER NOT NULL,
  type_unsupported INTEGER NOT NULL,
  dex_count INTEGER,
  reputation INTEGER NOT NULL,
  raw_response TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(package_name, file_path, sha256)
);
