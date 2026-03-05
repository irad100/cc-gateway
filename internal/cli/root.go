package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/irad100/cc-gateway/internal/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var cfg config.Config

// NewRootCmd creates the root "cc-gateway" command with global flags.
func NewRootCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "cc-gateway",
		Short: "Security observability and enforcement gateway for Claude Code",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			loaded, err := loadConfig(configPath)
			if err != nil {
				return err
			}
			cfg = loaded
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.PersistentFlags().StringVar(
		&configPath, "config", "cc-gateway.yaml",
		"path to config file",
	)

	cmd.AddCommand(newServeCmd())
	cmd.AddCommand(newVersionCmd())
	cmd.AddCommand(newPoliciesCmd())
	cmd.AddCommand(newLogsCmd())
	cmd.AddCommand(newUsersCmd())
	cmd.AddCommand(newMonitorCmd())

	return cmd
}

// loadConfig reads the YAML config file. If the file does not exist,
// it returns config.Default() without error.
func loadConfig(path string) (config.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return config.Default(), nil
		}
		return config.Config{}, fmt.Errorf("read config: %w", err)
	}

	c := config.Default()
	if err := yaml.Unmarshal(data, &c); err != nil {
		return config.Config{}, fmt.Errorf("parse config: %w", err)
	}
	return c, nil
}
