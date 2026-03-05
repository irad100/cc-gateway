package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/irad100/cc-gateway/internal/storage"
	"github.com/spf13/cobra"
)

func newLogsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Query the audit log",
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := storage.New(cfg.Storage.DSN)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer store.Close()

			filter := storage.EventFilter{}
			filter.UserID, _ = cmd.Flags().GetString("user")
			filter.ToolName, _ = cmd.Flags().GetString("tool")
			filter.PolicyAction, _ = cmd.Flags().GetString("status")
			filter.Limit, _ = cmd.Flags().GetInt("limit")

			if since, _ := cmd.Flags().GetString("since"); since != "" {
				t, err := parseDuration(since)
				if err != nil {
					return fmt.Errorf("parse --since: %w", err)
				}
				filter.Since = &t
			}
			if until, _ := cmd.Flags().GetString("until"); until != "" {
				t, err := parseDuration(until)
				if err != nil {
					return fmt.Errorf("parse --until: %w", err)
				}
				filter.Until = &t
			}

			ctx := context.Background()
			events, err := store.QueryEvents(ctx, filter)
			if err != nil {
				return fmt.Errorf("query events: %w", err)
			}

			format, _ := cmd.Flags().GetString("format")
			return renderEvents(events, format)
		},
	}
	cmd.Flags().String("user", "", "Filter by user")
	cmd.Flags().String("tool", "", "Filter by tool name")
	cmd.Flags().String("status", "", "Filter by action (allow/block)")
	cmd.Flags().String("since", "", "Time range start (e.g., 1h, 2024-01-01)")
	cmd.Flags().String("until", "", "Time range end")
	cmd.Flags().String("format", "table", "Output format: table, json")
	cmd.Flags().Int("limit", 100, "Max results")
	return cmd
}

func parseDuration(s string) (time.Time, error) {
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}
	for _, layout := range []string{
		time.DateOnly,
		time.DateTime,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time format: %q", s)
}

func renderEvents(events []storage.Event, format string) error {
	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(events)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tUSER\tTOOL\tACTION\tPOLICY")
	for _, e := range events {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			e.CreatedAt.Format("15:04:05"),
			e.UserID,
			e.ToolName,
			e.PolicyAction,
			e.PolicyName,
		)
	}
	return w.Flush()
}
