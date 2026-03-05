package cli

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/irad100/cc-gateway/internal/storage"
)

func TestRenderEventsCSV(t *testing.T) {
	events := []storage.Event{
		{
			CreatedAt:     time.Date(2026, 3, 5, 10, 30, 0, 0, time.UTC),
			UserID:        "alice",
			ToolName:      "Bash",
			PolicyAction:  "block",
			PolicyName:    "no-rm",
			PolicyMessage: "blocked rm -rf",
		},
		{
			CreatedAt:     time.Date(2026, 3, 5, 11, 0, 0, 0, time.UTC),
			UserID:        "bob",
			ToolName:      "Read",
			PolicyAction:  "allow",
			PolicyName:    "",
			PolicyMessage: "",
		},
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	origStdout := os.Stdout
	os.Stdout = w

	renderErr := renderEvents(events, "csv")

	w.Close()
	os.Stdout = origStdout

	if renderErr != nil {
		t.Fatalf("renderEvents: %v", renderErr)
	}

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines (header + 2 rows), got %d: %q",
			len(lines), output)
	}

	header := lines[0]
	if header != "time,user,tool,action,policy,message" {
		t.Errorf("unexpected header: %q", header)
	}

	if !strings.Contains(lines[1], "alice") {
		t.Errorf("expected alice in row 1: %q", lines[1])
	}
	if !strings.Contains(lines[1], "blocked rm -rf") {
		t.Errorf("expected message in row 1: %q", lines[1])
	}
	if !strings.Contains(lines[2], "bob") {
		t.Errorf("expected bob in row 2: %q", lines[2])
	}
}

func TestRenderEventsTable(t *testing.T) {
	events := []storage.Event{
		{
			CreatedAt:    time.Date(2026, 3, 5, 10, 30, 0, 0, time.UTC),
			UserID:       "alice",
			ToolName:     "Bash",
			PolicyAction: "allow",
			PolicyName:   "",
		},
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	origStdout := os.Stdout
	os.Stdout = w

	renderErr := renderEvents(events, "table")

	w.Close()
	os.Stdout = origStdout

	if renderErr != nil {
		t.Fatalf("renderEvents: %v", renderErr)
	}

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])

	if !strings.Contains(output, "TIME") {
		t.Errorf("expected table header, got: %q", output)
	}
	if !strings.Contains(output, "alice") {
		t.Errorf("expected alice in output: %q", output)
	}
}
