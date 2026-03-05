package metrics

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Collector runs aggregation queries against the events table.
type Collector struct {
	db *sql.DB
}

// NewCollector creates a Collector that queries the given database.
func NewCollector(db *sql.DB) *Collector {
	return &Collector{db: db}
}

// ToolStat holds the usage count for a single tool.
type ToolStat struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// PolicyStat holds the violation count for a single policy.
type PolicyStat struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// UserStat holds the violation count for a single user.
type UserStat struct {
	UserID string `json:"user_id"`
	Count  int    `json:"count"`
}

// Ratio holds blocked vs allowed event counts.
type Ratio struct {
	Blocked int `json:"blocked"`
	Allowed int `json:"allowed"`
	Total   int `json:"total"`
}

// HourStat holds the event count for a single hour of the day.
type HourStat struct {
	Hour  int `json:"hour"`
	Count int `json:"count"`
}

// Summary aggregates all metric queries into one response.
type Summary struct {
	ToolUsage          []ToolStat   `json:"tool_usage"`
	ViolationsByPolicy []PolicyStat `json:"violations_by_policy"`
	ViolationsByUser   []UserStat   `json:"violations_by_user"`
	SessionCount       int          `json:"session_count"`
	BlockAllowRatio    Ratio        `json:"block_allow_ratio"`
	HourlyActivity     []HourStat   `json:"hourly_activity"`
}

// ToolUsage returns tool names and their usage counts since the
// given time, ordered by count descending.
func (c *Collector) ToolUsage(
	ctx context.Context, since time.Time,
) ([]ToolStat, error) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT tool_name, COUNT(*) AS cnt
		FROM events
		WHERE created_at >= ? AND tool_name != ''
		GROUP BY tool_name
		ORDER BY cnt DESC
	`, since)
	if err != nil {
		return nil, fmt.Errorf("tool usage query: %w", err)
	}
	defer rows.Close()

	var stats []ToolStat
	for rows.Next() {
		var s ToolStat
		if err := rows.Scan(&s.Name, &s.Count); err != nil {
			return nil, fmt.Errorf("scan tool stat: %w", err)
		}
		stats = append(stats, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tool usage rows: %w", err)
	}
	return stats, nil
}

// ViolationsByPolicy returns policy names and their block counts
// since the given time, ordered by count descending.
func (c *Collector) ViolationsByPolicy(
	ctx context.Context, since time.Time,
) ([]PolicyStat, error) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT policy_name, COUNT(*) AS cnt
		FROM events
		WHERE created_at >= ?
			AND policy_action = 'block'
			AND policy_name != ''
		GROUP BY policy_name
		ORDER BY cnt DESC
	`, since)
	if err != nil {
		return nil, fmt.Errorf("violations by policy query: %w", err)
	}
	defer rows.Close()

	var stats []PolicyStat
	for rows.Next() {
		var s PolicyStat
		if err := rows.Scan(&s.Name, &s.Count); err != nil {
			return nil, fmt.Errorf("scan policy stat: %w", err)
		}
		stats = append(stats, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("violations by policy rows: %w", err)
	}
	return stats, nil
}

// ViolationsByUser returns user IDs and their block counts since
// the given time, ordered by count descending.
func (c *Collector) ViolationsByUser(
	ctx context.Context, since time.Time,
) ([]UserStat, error) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT user_id, COUNT(*) AS cnt
		FROM events
		WHERE created_at >= ?
			AND policy_action = 'block'
			AND user_id != ''
		GROUP BY user_id
		ORDER BY cnt DESC
	`, since)
	if err != nil {
		return nil, fmt.Errorf("violations by user query: %w", err)
	}
	defer rows.Close()

	var stats []UserStat
	for rows.Next() {
		var s UserStat
		if err := rows.Scan(&s.UserID, &s.Count); err != nil {
			return nil, fmt.Errorf("scan user stat: %w", err)
		}
		stats = append(stats, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("violations by user rows: %w", err)
	}
	return stats, nil
}

// SessionCount returns the number of distinct sessions since the
// given time.
func (c *Collector) SessionCount(
	ctx context.Context, since time.Time,
) (int, error) {
	var count int
	err := c.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT session_id)
		FROM events
		WHERE created_at >= ?
	`, since).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("session count query: %w", err)
	}
	return count, nil
}

// BlockAllowRatio returns the blocked, allowed, and total event
// counts since the given time.
func (c *Collector) BlockAllowRatio(
	ctx context.Context, since time.Time,
) (Ratio, error) {
	var r Ratio
	err := c.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN policy_action = 'block'
				THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN policy_action != 'block'
				THEN 1 ELSE 0 END), 0),
			COUNT(*)
		FROM events
		WHERE created_at >= ?
	`, since).Scan(&r.Blocked, &r.Allowed, &r.Total)
	if err != nil {
		return Ratio{}, fmt.Errorf("block allow ratio query: %w", err)
	}
	return r, nil
}

// HourlyActivity returns event counts grouped by hour of day
// since the given time.
func (c *Collector) HourlyActivity(
	ctx context.Context, since time.Time,
) ([]HourStat, error) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT CAST(substr(replace(created_at, 'T', ' '), 12, 2) AS INTEGER),
			COUNT(*)
		FROM events
		WHERE created_at >= ?
		GROUP BY substr(replace(created_at, 'T', ' '), 12, 2)
		ORDER BY 1
	`, since)
	if err != nil {
		return nil, fmt.Errorf("hourly activity query: %w", err)
	}
	defer rows.Close()

	var stats []HourStat
	for rows.Next() {
		var s HourStat
		if err := rows.Scan(&s.Hour, &s.Count); err != nil {
			return nil, fmt.Errorf("scan hour stat: %w", err)
		}
		stats = append(stats, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("hourly activity rows: %w", err)
	}
	return stats, nil
}

// Summary runs all metric queries and returns the combined result.
func (c *Collector) Summary(
	ctx context.Context, since time.Time,
) (*Summary, error) {
	toolUsage, err := c.ToolUsage(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("summary tool usage: %w", err)
	}

	byPolicy, err := c.ViolationsByPolicy(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("summary violations by policy: %w", err)
	}

	byUser, err := c.ViolationsByUser(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("summary violations by user: %w", err)
	}

	sessions, err := c.SessionCount(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("summary session count: %w", err)
	}

	ratio, err := c.BlockAllowRatio(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("summary block allow ratio: %w", err)
	}

	hourly, err := c.HourlyActivity(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("summary hourly activity: %w", err)
	}

	return &Summary{
		ToolUsage:          toolUsage,
		ViolationsByPolicy: byPolicy,
		ViolationsByUser:   byUser,
		SessionCount:       sessions,
		BlockAllowRatio:    ratio,
		HourlyActivity:     hourly,
	}, nil
}
