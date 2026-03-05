package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy defines a single rule evaluated against hook events.
type Policy struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Enabled     bool        `yaml:"enabled"`
	Event       string      `yaml:"event"`
	Matcher     string      `yaml:"matcher"`
	Conditions  []Condition `yaml:"conditions"`
	Action      string      `yaml:"action"`
	Message     string      `yaml:"message"`
	Priority    int         `yaml:"priority"`
}

// UnmarshalYAML defaults Enabled to true.
func (p *Policy) UnmarshalYAML(unmarshal func(any) error) error {
	type raw Policy
	r := raw{Enabled: true}
	if err := unmarshal(&r); err != nil {
		return err
	}
	*p = Policy(r)
	return nil
}

// Condition matches a field value against a precompiled regex.
type Condition struct {
	Field   string         `yaml:"field"`
	Pattern string         `yaml:"pattern"`
	Negate  bool           `yaml:"negate"`
	re      *regexp.Regexp
}

// EvalResult holds the outcome of policy evaluation.
type EvalResult struct {
	Action     string
	PolicyName string
	Message    string
}

type policyFile struct {
	Policies []Policy `yaml:"policies"`
}

// ParseYAML unmarshals YAML policy data and precompiles
// regex patterns for each condition.
func ParseYAML(data []byte) ([]Policy, error) {
	var pf policyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("unmarshal policies: %w", err)
	}

	validActions := map[string]bool{"allow": true, "block": true}
	validEvents := map[string]bool{
		"PreToolUse": true, "PostToolUse": true,
		"Notification": true, "Stop": true,
	}

	for i := range pf.Policies {
		p := &pf.Policies[i]
		if !validActions[p.Action] {
			return nil, fmt.Errorf(
				"policy %q: invalid action %q (must be allow or block)",
				p.Name, p.Action,
			)
		}
		if !validEvents[p.Event] {
			return nil, fmt.Errorf(
				"policy %q: invalid event %q", p.Name, p.Event,
			)
		}
		for j := range pf.Policies[i].Conditions {
			c := &pf.Policies[i].Conditions[j]
			re, err := regexp.Compile(c.Pattern)
			if err != nil {
				return nil, fmt.Errorf(
					"policy %q condition %d: invalid regex %q: %w",
					pf.Policies[i].Name, j, c.Pattern, err,
				)
			}
			c.re = re
		}
	}

	return pf.Policies, nil
}

// LoadFromDir reads all .yaml and .yml files from dir,
// parses each, and returns the combined list of policies.
func LoadFromDir(dir string) ([]Policy, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read policy dir %q: %w", dir, err)
	}

	var all []Policy
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf(
				"read policy file %q: %w", entry.Name(), err,
			)
		}

		policies, err := ParseYAML(data)
		if err != nil {
			return nil, fmt.Errorf(
				"parse policy file %q: %w", entry.Name(), err,
			)
		}
		all = append(all, policies...)
	}

	return all, nil
}
