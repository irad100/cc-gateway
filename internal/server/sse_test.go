package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBrokerPublishAndReceive(t *testing.T) {
	b := NewBroker(slog.Default())
	ch := b.subscribe()
	defer b.unsubscribe(ch)

	ev := SSEEvent{
		ID:   1,
		Type: "PreToolUse",
		Data: json.RawMessage(`{"tool":"Bash"}`),
	}
	b.Publish(ev)

	select {
	case got := <-ch:
		if got.ID != 1 {
			t.Errorf("ID: got %d, want 1", got.ID)
		}
		if got.Type != "PreToolUse" {
			t.Errorf("Type: got %q, want PreToolUse", got.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestBrokerClientCount(t *testing.T) {
	b := NewBroker(slog.Default())
	if b.ClientCount() != 0 {
		t.Fatalf("expected 0 clients, got %d", b.ClientCount())
	}

	ch1 := b.subscribe()
	ch2 := b.subscribe()
	if b.ClientCount() != 2 {
		t.Fatalf("expected 2 clients, got %d", b.ClientCount())
	}

	b.unsubscribe(ch1)
	b.unsubscribe(ch2)
	if b.ClientCount() != 0 {
		t.Fatalf("expected 0 clients, got %d", b.ClientCount())
	}
}

func TestBrokerSSEHandler(t *testing.T) {
	b := NewBroker(slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/events/stream", nil)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		b.ServeHTTP(rec, req)
		close(done)
	}()

	// Give the handler time to subscribe
	time.Sleep(50 * time.Millisecond)

	b.Publish(SSEEvent{
		ID:   42,
		Type: "test",
		Data: json.RawMessage(`{"hello":"world"}`),
	})

	// Give the handler time to write
	time.Sleep(50 * time.Millisecond)

	cancel()
	<-done

	body := rec.Body.String()
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("expected Content-Type text/event-stream, got %q", ct)
	}
	if !strings.Contains(body, "id: 42") {
		t.Errorf("expected 'id: 42' in body, got:\n%s", body)
	}
	if !strings.Contains(body, `"hello":"world"`) {
		t.Errorf("expected event data in body, got:\n%s", body)
	}
}
