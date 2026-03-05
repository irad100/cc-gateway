package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf(
				"cc-gateway version %s (commit: %s, built: %s)\n",
				Version, Commit, Date,
			)
		},
	}
}
