package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/irad100/cc-gateway/internal/policy"
	"github.com/spf13/cobra"
)

func newPoliciesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policies",
		Short: "Manage security policies",
	}
	cmd.AddCommand(newPoliciesListCmd())
	cmd.AddCommand(newPoliciesValidateCmd())
	cmd.AddCommand(newPoliciesTestCmd())
	return cmd
}

func newPoliciesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all loaded policies",
		RunE: func(_ *cobra.Command, _ []string) error {
			policies, err := policy.LoadFromDir(cfg.Policies.Dir)
			if err != nil {
				return fmt.Errorf("load policies: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tEVENT\tMATCHER\tACTION\tENABLED")
			for _, p := range policies {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%v\n",
					p.Name, p.Event, p.Matcher, p.Action, p.Enabled,
				)
			}
			return w.Flush()
		},
	}
}

func newPoliciesValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [file...]",
		Short: "Validate policy YAML files",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			allValid := true
			for _, path := range args {
				data, err := os.ReadFile(path)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
					allValid = false
					continue
				}
				_, err = policy.ParseYAML(data)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: INVALID: %v\n", path, err)
					allValid = false
				} else {
					fmt.Printf("%s: valid\n", path)
				}
			}
			if !allValid {
				return fmt.Errorf("one or more policy files are invalid")
			}
			return nil
		},
	}
}

func newPoliciesTestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test a policy against a sample event",
		RunE: func(cmd *cobra.Command, _ []string) error {
			eventJSON, _ := cmd.Flags().GetString("event")
			policyName, _ := cmd.Flags().GetString("policy")

			var input struct {
				Event    string          `json:"event"`
				ToolName string          `json:"tool_name"`
				Input    json.RawMessage `json:"tool_input"`
			}
			if err := json.Unmarshal([]byte(eventJSON), &input); err != nil {
				return fmt.Errorf("parse event JSON: %w", err)
			}

			policies, err := policy.LoadFromDir(cfg.Policies.Dir)
			if err != nil {
				return fmt.Errorf("load policies: %w", err)
			}

			if policyName != "" {
				var filtered []policy.Policy
				for _, p := range policies {
					if p.Name == policyName {
						filtered = append(filtered, p)
					}
				}
				policies = filtered
			}

			engine := policy.NewEngine(policies, "allow")
			result := engine.Evaluate(
				input.Event, input.ToolName, input.Input, policy.EvalMeta{},
			)

			fmt.Printf("Action: %s\n", result.Action)
			if result.PolicyName != "" {
				fmt.Printf("Policy: %s\n", result.PolicyName)
			}
			if result.Message != "" {
				fmt.Printf("Message: %s\n", result.Message)
			}
			return nil
		},
	}
	cmd.Flags().String("event", "", "JSON event to test (required)")
	cmd.Flags().String("policy", "", "Specific policy to test against")
	_ = cmd.MarkFlagRequired("event")
	return cmd
}
