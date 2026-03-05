package cli

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/irad100/cc-gateway/internal/tui"
	"github.com/spf13/cobra"
)

func newMonitorCmd() *cobra.Command {
	var (
		serverURL string
		token     string
	)

	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Launch the live TUI dashboard",
		RunE: func(cmd *cobra.Command, _ []string) error {
			m := tui.New(serverURL)
			p := tea.NewProgram(m, tea.WithAltScreen())

			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()

			go tui.ListenSSE(ctx, serverURL, token, p)
			go tui.FetchSessions(ctx, serverURL, token, p)
			go tui.FetchMetrics(ctx, serverURL, token, p)

			if _, err := p.Run(); err != nil {
				return fmt.Errorf("monitor: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(
		&serverURL, "url", "http://localhost:8080",
		"gateway server URL",
	)
	cmd.Flags().StringVar(
		&token, "token", "",
		"bearer token for API authentication",
	)

	return cmd
}
