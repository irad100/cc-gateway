package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Event represents a single hook event stored in the database.
type Event struct {
	ID            int64
	SessionID     string
	UserID        string
	EventType     string
	ToolName      string
	ToolParams    string
	PolicyName    string
	PolicyAction  string
	PolicyMessage string
	CreatedAt     time.Time
}

// EventFilter defines optional filters for querying events.
type EventFilter struct {
	UserID       string
	SessionID    string
	EventType    string
	ToolName     string
	PolicyAction string
	Since        *time.Time
	Until        *time.Time
	Limit        int
	Offset       int
}

// User represents an aggregated user record derived from events.
type User struct {
	ID           string
	DisplayName  string
	CreatedAt    time.Time
	LastActiveAt time.Time
	EventCount   int
}

// UserActivity holds aggregated activity stats for a single user.
type UserActivity struct {
	SessionCount   int
	EventCount     int
	ViolationCount int
	ToolUsage      map[string]int
}

// Store manages the SQLite event database.
type Store struct {
	db          *sql.DB
	insertEvent *sql.Stmt
}

// New opens the SQLite database at dsn, configures PRAGMAs, runs
// migrations, and prepares the insert statement.
func New(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("exec %q: %w", p, err)
		}
	}

	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	stmt, err := db.Prepare(`
		INSERT INTO events (
			session_id, user_id, event_type, tool_name,
			tool_params, policy_name, policy_action,
			policy_message, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("prepare insert: %w", err)
	}

	return &Store{db: db, insertEvent: stmt}, nil
}

// DB returns the underlying database connection for use by other
// packages that need direct SQL access (e.g., metrics).
func (s *Store) DB() *sql.DB {
	return s.db
}

// Close releases the prepared statement and closes the database.
func (s *Store) Close() error {
	s.insertEvent.Close()
	return s.db.Close()
}

// InsertEvent inserts an event and sets e.ID from the result.
func (s *Store) InsertEvent(ctx context.Context, e *Event) error {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	res, err := s.insertEvent.ExecContext(ctx,
		e.SessionID, e.UserID, e.EventType, e.ToolName,
		e.ToolParams, e.PolicyName, e.PolicyAction,
		e.PolicyMessage, e.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("last insert id: %w", err)
	}
	e.ID = id
	return nil
}

// QueryEvents returns events matching the given filter, ordered by
// created_at DESC. Default limit is 100.
func (s *Store) QueryEvents(
	ctx context.Context, f EventFilter,
) ([]Event, error) {
	var clauses []string
	var args []any

	if f.UserID != "" {
		clauses = append(clauses, "user_id = ?")
		args = append(args, f.UserID)
	}
	if f.SessionID != "" {
		clauses = append(clauses, "session_id = ?")
		args = append(args, f.SessionID)
	}
	if f.EventType != "" {
		clauses = append(clauses, "event_type = ?")
		args = append(args, f.EventType)
	}
	if f.ToolName != "" {
		clauses = append(clauses, "tool_name = ?")
		args = append(args, f.ToolName)
	}
	if f.PolicyAction != "" {
		clauses = append(clauses, "policy_action = ?")
		args = append(args, f.PolicyAction)
	}
	if f.Since != nil {
		clauses = append(clauses, "created_at >= ?")
		args = append(args, *f.Since)
	}
	if f.Until != nil {
		clauses = append(clauses, "created_at <= ?")
		args = append(args, *f.Until)
	}

	query := "SELECT id, session_id, user_id, event_type, tool_name, " +
		"tool_params, policy_name, policy_action, policy_message, " +
		"created_at FROM events"
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY created_at DESC"

	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	query += " LIMIT ? OFFSET ?"
	args = append(args, limit, f.Offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(
			&e.ID, &e.SessionID, &e.UserID, &e.EventType,
			&e.ToolName, &e.ToolParams, &e.PolicyName,
			&e.PolicyAction, &e.PolicyMessage, &e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// ListUsers returns aggregated user records from the events table,
// excluding events with an empty user_id.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_id, MIN(created_at), MAX(created_at), COUNT(*)
		FROM events
		WHERE user_id != ''
		GROUP BY user_id
	`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(
			&u.ID, &u.CreatedAt, &u.LastActiveAt, &u.EventCount,
		); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		u.DisplayName = u.ID
		users = append(users, u)
	}
	return users, rows.Err()
}

// UserActivity returns aggregated activity stats for the given user.
func (s *Store) UserActivity(
	ctx context.Context, userID string,
) (*UserActivity, error) {
	var a UserActivity

	err := s.db.QueryRowContext(ctx, `
		SELECT
			COUNT(DISTINCT session_id),
			COUNT(*),
			SUM(CASE WHEN policy_action = 'block' THEN 1 ELSE 0 END)
		FROM events
		WHERE user_id = ?
	`, userID).Scan(&a.SessionCount, &a.EventCount, &a.ViolationCount)
	if err != nil {
		return nil, fmt.Errorf("user activity summary: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT tool_name, COUNT(*)
		FROM events
		WHERE user_id = ? AND tool_name != ''
		GROUP BY tool_name
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("user tool usage: %w", err)
	}
	defer rows.Close()

	a.ToolUsage = make(map[string]int)
	for rows.Next() {
		var name string
		var count int
		if err := rows.Scan(&name, &count); err != nil {
			return nil, fmt.Errorf("scan tool usage: %w", err)
		}
		a.ToolUsage[name] = count
	}
	return &a, rows.Err()
}

// Session represents an aggregated session derived from events.
type Session struct {
	SessionID      string    `json:"session_id"`
	UserID         string    `json:"user_id"`
	StartedAt      time.Time `json:"started_at"`
	EndedAt        time.Time `json:"ended_at"`
	EventCount     int       `json:"event_count"`
	ViolationCount int       `json:"violation_count"`
}

// ListSessions returns aggregated session records ordered by most
// recent activity, with pagination via limit and offset.
func (s *Store) ListSessions(
	ctx context.Context, limit, offset int,
) ([]Session, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT session_id, user_id,
			MIN(created_at), MAX(created_at),
			COUNT(*),
			SUM(CASE WHEN policy_action = 'block' THEN 1 ELSE 0 END)
		FROM events
		GROUP BY session_id
		ORDER BY MAX(created_at) DESC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var sess Session
		var startedAt, endedAt string
		if err := rows.Scan(
			&sess.SessionID, &sess.UserID,
			&startedAt, &endedAt,
			&sess.EventCount, &sess.ViolationCount,
		); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sess.StartedAt, _ = time.Parse(time.RFC3339Nano, startedAt)
		sess.EndedAt, _ = time.Parse(time.RFC3339Nano, endedAt)
		sessions = append(sessions, sess)
	}
	return sessions, rows.Err()
}

// PruneOldEvents deletes events created before the given time and
// returns the number of rows deleted.
func (s *Store) PruneOldEvents(
	ctx context.Context, before time.Time,
) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM events WHERE created_at < ?", before,
	)
	if err != nil {
		return 0, fmt.Errorf("prune events: %w", err)
	}
	return res.RowsAffected()
}
