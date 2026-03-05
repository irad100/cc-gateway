package policy

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watcher monitors a directory for policy file changes and
// hot-reloads the Engine when .yaml/.yml files are modified.
type Watcher struct {
	engine  *Engine
	dir     string
	watcher *fsnotify.Watcher
	logger  *slog.Logger
}

// NewWatcher creates a Watcher that reloads policies in engine
// whenever files change in dir.
func NewWatcher(
	engine *Engine,
	dir string,
	logger *slog.Logger,
) (*Watcher, error) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := fw.Add(dir); err != nil {
		fw.Close()
		return nil, err
	}
	return &Watcher{
		engine:  engine,
		dir:     dir,
		watcher: fw,
		logger:  logger,
	}, nil
}

// Run watches for file changes until ctx is cancelled. It debounces
// rapid changes and reloads policies on Create, Write, Remove, and
// Rename events for .yaml/.yml files.
func (w *Watcher) Run(ctx context.Context) error {
	var mu sync.Mutex
	var debounce *time.Timer

	reload := func() {
		policies, err := LoadFromDir(w.dir)
		if err != nil {
			w.logger.Error("policy reload failed",
				"dir", w.dir, "error", err)
			return
		}
		w.engine.SetPolicies(policies)
		w.logger.Info("policies reloaded",
			"dir", w.dir, "count", len(policies))
	}

	for {
		select {
		case <-ctx.Done():
			mu.Lock()
			if debounce != nil {
				debounce.Stop()
			}
			mu.Unlock()
			return nil

		case event, ok := <-w.watcher.Events:
			if !ok {
				return nil
			}
			if !isRelevantEvent(event) {
				continue
			}
			mu.Lock()
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(
				100*time.Millisecond, reload,
			)
			mu.Unlock()

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return nil
			}
			w.logger.Error("fsnotify error", "error", err)
		}
	}
}

// Close shuts down the underlying fsnotify watcher.
func (w *Watcher) Close() error {
	return w.watcher.Close()
}

func isRelevantEvent(event fsnotify.Event) bool {
	relevantOps := fsnotify.Create | fsnotify.Write |
		fsnotify.Remove | fsnotify.Rename
	if event.Op&relevantOps == 0 {
		return false
	}
	ext := strings.ToLower(filepath.Ext(event.Name))
	return ext == ".yaml" || ext == ".yml"
}
