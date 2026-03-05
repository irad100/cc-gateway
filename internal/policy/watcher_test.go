package policy

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const validPolicy = `policies:
  - name: test-policy
    event: PreToolUse
    matcher: Bash
    action: block
    message: blocked
`

func TestWatcherReloadsOnChange(t *testing.T) {
	dir := t.TempDir()

	initial := `policies:
  - name: initial
    event: PreToolUse
    matcher: Bash
    action: allow
    message: allowed
`
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	policies, err := LoadFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(policies)

	logger := slog.New(slog.NewTextHandler(
		os.Stderr, &slog.HandlerOptions{Level: slog.LevelError},
	))
	w, err := NewWatcher(engine, dir, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = w.Run(ctx)
		close(done)
	}()

	// Give fsnotify time to start watching.
	time.Sleep(50 * time.Millisecond)

	if err := os.WriteFile(
		path, []byte(validPolicy), 0o644,
	); err != nil {
		t.Fatal(err)
	}

	// Wait for debounce (100ms) plus margin.
	time.Sleep(300 * time.Millisecond)

	got := engine.Policies()
	if len(got) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(got))
	}
	if got[0].Name != "test-policy" {
		t.Errorf(
			"expected policy name %q, got %q",
			"test-policy", got[0].Name,
		)
	}
	if got[0].Action != "block" {
		t.Errorf(
			"expected action %q, got %q",
			"block", got[0].Action,
		)
	}

	cancel()
	<-done
}

func TestWatcherIgnoresInvalidYAML(t *testing.T) {
	dir := t.TempDir()

	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(
		path, []byte(validPolicy), 0o644,
	); err != nil {
		t.Fatal(err)
	}

	policies, err := LoadFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(policies)

	logger := slog.New(slog.NewTextHandler(
		os.Stderr, &slog.HandlerOptions{Level: slog.LevelError},
	))
	w, err := NewWatcher(engine, dir, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = w.Run(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	invalid := `policies:
  - name: [[[invalid yaml
    event: !!!
`
	if err := os.WriteFile(
		path, []byte(invalid), 0o644,
	); err != nil {
		t.Fatal(err)
	}

	time.Sleep(300 * time.Millisecond)

	got := engine.Policies()
	if len(got) != 1 {
		t.Fatalf("expected 1 policy (unchanged), got %d", len(got))
	}
	if got[0].Name != "test-policy" {
		t.Errorf(
			"expected policy name %q, got %q",
			"test-policy", got[0].Name,
		)
	}

	cancel()
	<-done
}
