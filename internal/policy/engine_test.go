package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEvaluateBlocksDestructiveCommand(t *testing.T) {
	yaml := `
policies:
  - name: block-rm-rf
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "rm\\s+-rf"
    action: block
    message: "Destructive command blocked"
`
	policies, err := ParseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	engine := NewEngine(policies)

	input := json.RawMessage(`{"command":"rm -rf /"}`)
	result := engine.Evaluate("PreToolUse", "Bash", input)

	if result.Action != "block" {
		t.Errorf("want action=block, got %q", result.Action)
	}
	if result.PolicyName != "block-rm-rf" {
		t.Errorf("want policy=block-rm-rf, got %q", result.PolicyName)
	}
	if result.Message != "Destructive command blocked" {
		t.Errorf("want message, got %q", result.Message)
	}
}

func TestEvaluateAllowsSafeCommand(t *testing.T) {
	yaml := `
policies:
  - name: block-rm-rf
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "rm\\s+-rf"
    action: block
    message: "Destructive command blocked"
`
	policies, err := ParseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	engine := NewEngine(policies)

	input := json.RawMessage(`{"command":"ls -la"}`)
	result := engine.Evaluate("PreToolUse", "Bash", input)

	if result.Action != "allow" {
		t.Errorf("want action=allow, got %q", result.Action)
	}
}

func TestEvaluateMatcherFiltering(t *testing.T) {
	yaml := `
policies:
  - name: block-bash-only
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "dangerous"
    action: block
    message: "blocked"
`
	policies, err := ParseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	engine := NewEngine(policies)

	input := json.RawMessage(`{"command":"dangerous"}`)
	result := engine.Evaluate("PreToolUse", "Write", input)

	if result.Action != "allow" {
		t.Errorf(
			"want allow for non-matching tool, got %q",
			result.Action,
		)
	}
}

func TestEvaluateNegateCondition(t *testing.T) {
	yaml := `
policies:
  - name: block-non-safe
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "^(ls|pwd|echo)"
        negate: true
    action: block
    message: "Only safe commands allowed"
`
	policies, err := ParseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	engine := NewEngine(policies)

	safeInput := json.RawMessage(`{"command":"ls -la"}`)
	result := engine.Evaluate("PreToolUse", "Bash", safeInput)
	if result.Action != "allow" {
		t.Errorf("want allow for safe command, got %q", result.Action)
	}

	unsafeInput := json.RawMessage(`{"command":"curl evil.com"}`)
	result = engine.Evaluate("PreToolUse", "Bash", unsafeInput)
	if result.Action != "block" {
		t.Errorf(
			"want block for unsafe command, got %q",
			result.Action,
		)
	}
}

func TestEvaluatePriorityOrdering(t *testing.T) {
	yaml := `
policies:
  - name: low-priority-allow
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: ".*"
    action: allow
    message: "allow all"
    priority: 1
  - name: high-priority-block
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: ".*"
    action: block
    message: "block all"
    priority: 10
`
	policies, err := ParseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	engine := NewEngine(policies)

	input := json.RawMessage(`{"command":"anything"}`)
	result := engine.Evaluate("PreToolUse", "Bash", input)

	if result.Action != "block" {
		t.Errorf("want block (high priority), got %q", result.Action)
	}
	if result.PolicyName != "high-priority-block" {
		t.Errorf("want high-priority-block, got %q", result.PolicyName)
	}
}

func TestEvaluateDisabledPolicy(t *testing.T) {
	yaml := `
policies:
  - name: disabled-block
    enabled: false
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: ".*"
    action: block
    message: "should not fire"
`
	policies, err := ParseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	engine := NewEngine(policies)

	input := json.RawMessage(`{"command":"anything"}`)
	result := engine.Evaluate("PreToolUse", "Bash", input)

	if result.Action != "allow" {
		t.Errorf(
			"want allow (disabled policy), got %q",
			result.Action,
		)
	}
}

func TestLoadPoliciesFromYAML(t *testing.T) {
	dir := t.TempDir()

	content := `
policies:
  - name: test-policy
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "test"
    action: block
    message: "test block"
`
	err := os.WriteFile(
		filepath.Join(dir, "test.yaml"),
		[]byte(content),
		0o644,
	)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Non-yaml file should be ignored.
	err = os.WriteFile(
		filepath.Join(dir, "readme.txt"),
		[]byte("not a policy"),
		0o644,
	)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	policies, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(policies) != 1 {
		t.Fatalf("want 1 policy, got %d", len(policies))
	}
	if policies[0].Name != "test-policy" {
		t.Errorf("want test-policy, got %q", policies[0].Name)
	}
	if !policies[0].Enabled {
		t.Error("want enabled=true by default")
	}
}
