package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Engine evaluates hook events against a sorted list of policies.
type Engine struct {
	mu       sync.RWMutex
	policies []Policy
}

// NewEngine creates an Engine with the given policies sorted by
// priority (descending), then name (ascending).
func NewEngine(policies []Policy) *Engine {
	e := &Engine{}
	e.SetPolicies(policies)
	return e
}

// SetPolicies replaces the policy list, sorting by priority desc
// then name asc.
func (e *Engine) SetPolicies(policies []Policy) {
	sorted := make([]Policy, len(policies))
	copy(sorted, policies)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority > sorted[j].Priority
		}
		return sorted[i].Name < sorted[j].Name
	})
	e.mu.Lock()
	e.policies = sorted
	e.mu.Unlock()
}

// Policies returns a copy of the current policy list.
func (e *Engine) Policies() []Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Policy, len(e.policies))
	copy(out, e.policies)
	return out
}

// Evaluate checks the event against all policies and returns the
// result of the first matching policy. Returns an allow result if
// no policy matches.
func (e *Engine) Evaluate(
	event, toolName string,
	toolInput json.RawMessage,
) EvalResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, p := range e.policies {
		if !p.Enabled {
			continue
		}
		if p.Event != event {
			continue
		}
		if p.Matcher != "" && p.Matcher != toolName {
			continue
		}
		if matchesAll(p.Conditions, toolInput) {
			return EvalResult{
				Action:     p.Action,
				PolicyName: p.Name,
				Message:    p.Message,
			}
		}
	}

	return EvalResult{Action: "allow"}
}

// matchesAll returns true when every condition matches the input.
func matchesAll(
	conditions []Condition,
	toolInput json.RawMessage,
) bool {
	var inputMap map[string]any
	if len(toolInput) > 0 {
		if err := json.Unmarshal(toolInput, &inputMap); err != nil {
			return false
		}
	}

	for _, c := range conditions {
		val := extractField(inputMap, c.Field)
		matched := c.re.MatchString(val)
		if c.Negate {
			matched = !matched
		}
		if !matched {
			return false
		}
	}
	return true
}

// extractField resolves a dot-separated path against a nested map.
func extractField(m map[string]any, field string) string {
	parts := strings.Split(field, ".")
	var current any = m

	for _, part := range parts {
		cm, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = cm[part]
		if !ok {
			return ""
		}
	}

	return fmt.Sprintf("%v", current)
}
