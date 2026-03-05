package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// SSEEvent is a pre-serialized event for broadcasting to SSE clients.
type SSEEvent struct {
	ID   int64           `json:"id"`
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// Broker fans out SSE events to connected clients.
type Broker struct {
	mu      sync.RWMutex
	clients map[chan SSEEvent]struct{}
	logger  *slog.Logger
}

// NewBroker creates an SSE broker.
func NewBroker(logger *slog.Logger) *Broker {
	return &Broker{
		clients: make(map[chan SSEEvent]struct{}),
		logger:  logger,
	}
}

// Publish sends an event to all connected clients.
// Drops events for slow clients.
func (b *Broker) Publish(ev SSEEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.clients {
		select {
		case ch <- ev:
		default:
			// Slow client, drop event
		}
	}
}

func (b *Broker) subscribe() chan SSEEvent {
	ch := make(chan SSEEvent, 128)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *Broker) unsubscribe(ch chan SSEEvent) {
	b.mu.Lock()
	delete(b.clients, ch)
	b.mu.Unlock()
	close(ch)
}

// ClientCount returns the number of connected SSE clients.
func (b *Broker) ClientCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients)
}

// ServeHTTP handles SSE client connections at GET /events/stream.
func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := b.subscribe()
	defer b.unsubscribe(ch)

	b.logger.Info("SSE client connected",
		"remote", r.RemoteAddr,
		"clients", b.ClientCount(),
	)

	// Send initial keepalive
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	keepalive := time.NewTicker(30 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			b.logger.Info("SSE client disconnected",
				"remote", r.RemoteAddr,
			)
			return

		case ev := <-ch:
			data, err := json.Marshal(ev)
			if err != nil {
				b.logger.Error("marshal SSE event", "error", err)
				continue
			}
			fmt.Fprintf(w, "id: %d\ndata: %s\n\n", ev.ID, data)
			flusher.Flush()

		case <-keepalive.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
