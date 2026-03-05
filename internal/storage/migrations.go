package storage

// schemaSQL defines the events table and its indexes.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    user_id TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL,
    tool_name TEXT NOT NULL DEFAULT '',
    tool_params TEXT NOT NULL DEFAULT '{}',
    policy_name TEXT NOT NULL DEFAULT '',
    policy_action TEXT NOT NULL DEFAULT '',
    policy_message TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
`
