package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new cc-gateway installation",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runInit()
		},
	}
	cmd.PersistentPreRunE = func(_ *cobra.Command, _ []string) error {
		return nil
	}
	return cmd
}

func runInit() error {
	configPath := "cc-gateway.yaml"
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("%s already exists", configPath)
	}

	configContent := `# cc-gateway configuration
server:
  addr: ":8080"
  read_timeout: 30s
  write_timeout: 30s

auth:
  bearer_tokens: []
  # - token_hash: "<sha256 hash of token>"
  #   user_id: "user@example.com"

storage:
  dsn: "cc-gateway.db"
  retention: 2160h  # 90 days

policies:
  dir: "./policies"
  watch: true
  default_action: allow

logging:
  level: info
  format: json
  output: stdout
`
	if err := os.WriteFile(
		configPath, []byte(configContent), 0644,
	); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Printf("Created %s\n", configPath)

	policiesDir := "policies"
	if err := os.MkdirAll(policiesDir, 0755); err != nil {
		return fmt.Errorf("create policies dir: %w", err)
	}

	defaultPolicy := filepath.Join(policiesDir, "default.yaml")
	if _, err := os.Stat(defaultPolicy); os.IsNotExist(err) {
		content := defaultPolicyContent()
		if err := os.WriteFile(
			defaultPolicy, []byte(content), 0644,
		); err != nil {
			return fmt.Errorf("write default policy: %w", err)
		}
		fmt.Printf("Created %s\n", defaultPolicy)
	}

	fmt.Println("\ncc-gateway initialized! Run 'cc-gateway serve' to start.")
	return nil
}

func defaultPolicyContent() string {
	return `policies:
  - name: block-destructive-commands
    description: Block destructive shell commands
    enabled: true
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "rm\\s+-rf\\s+/"
    action: block
    message: "Destructive rm -rf on root paths is not allowed"
    priority: 100

  - name: block-disk-format
    description: Block disk formatting commands
    enabled: true
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "(mkfs|dd\\s+if=.*of=/dev)"
    action: block
    message: "Disk formatting commands are not allowed"
    priority: 100

  - name: block-secret-file-access
    description: Block reading sensitive credential files
    enabled: true
    event: PreToolUse
    matcher: Read
    conditions:
      - field: file_path
        pattern: "\\.(env|pem|key|p12|pfx)$"
    action: block
    message: "Reading credential files is not allowed"
    priority: 90

  - name: block-secret-file-write
    description: Block writing to sensitive credential files
    enabled: true
    event: PreToolUse
    matcher: Write
    conditions:
      - field: file_path
        pattern: "\\.(env|pem|key|p12|pfx)$"
    action: block
    message: "Writing to credential files is not allowed"
    priority: 90
`
}
