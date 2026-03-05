package cli

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/irad100/cc-gateway/internal/storage"
	"github.com/spf13/cobra"
)

func newUsersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "users",
		Short: "Manage users",
	}
	cmd.AddCommand(newUsersListCmd())
	cmd.AddCommand(newUsersActivityCmd())
	return cmd
}

func newUsersListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all registered users",
		RunE: func(_ *cobra.Command, _ []string) error {
			store, err := storage.New(cfg.Storage.DSN)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer store.Close()

			ctx := context.Background()
			users, err := store.ListUsers(ctx)
			if err != nil {
				return fmt.Errorf("list users: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "USER\tEVENTS\tFIRST SEEN\tLAST ACTIVE")
			for _, u := range users {
				fmt.Fprintf(w, "%s\t%d\t%s\t%s\n",
					u.ID,
					u.EventCount,
					u.CreatedAt.Format("2006-01-02"),
					u.LastActiveAt.Format("2006-01-02 15:04"),
				)
			}
			return w.Flush()
		},
	}
}

func newUsersActivityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "activity",
		Short: "Show detailed activity for a specific user",
		RunE: func(cmd *cobra.Command, _ []string) error {
			userID, _ := cmd.Flags().GetString("user")
			if userID == "" {
				return fmt.Errorf("--user flag is required")
			}

			store, err := storage.New(cfg.Storage.DSN)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer store.Close()

			ctx := context.Background()
			activity, err := store.UserActivity(ctx, userID)
			if err != nil {
				return fmt.Errorf("user activity: %w", err)
			}

			fmt.Printf("User: %s\n", userID)
			fmt.Printf("Sessions: %d\n", activity.SessionCount)
			fmt.Printf("Events: %d\n", activity.EventCount)
			fmt.Printf("Violations: %d\n", activity.ViolationCount)
			if len(activity.ToolUsage) > 0 {
				fmt.Println("\nTool Usage:")
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				for tool, count := range activity.ToolUsage {
					fmt.Fprintf(w, "  %s\t%d\n", tool, count)
				}
				w.Flush()
			}
			return nil
		},
	}
	cmd.Flags().String("user", "", "User ID")
	return cmd
}
