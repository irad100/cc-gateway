package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/irad100/cc-gateway/internal/auth"
	"github.com/irad100/cc-gateway/internal/config"
	"github.com/irad100/cc-gateway/internal/metrics"
	"github.com/irad100/cc-gateway/internal/policy"
	"github.com/irad100/cc-gateway/internal/server"
	"github.com/irad100/cc-gateway/internal/storage"
	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	var (
		addr       string
		db         string
		policiesDir string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the gateway HTTP server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			applyServeOverrides(addr, db, policiesDir)
			return runServe(cmd.Context())
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "", "listen address (overrides config)")
	cmd.Flags().StringVar(&db, "db", "", "database DSN (overrides config)")
	cmd.Flags().StringVar(
		&policiesDir, "policies-dir", "",
		"policies directory (overrides config)",
	)

	return cmd
}

func applyServeOverrides(addr, db, policiesDir string) {
	if addr != "" {
		cfg.Server.Addr = addr
	}
	if db != "" {
		cfg.Storage.DSN = db
	}
	if policiesDir != "" {
		cfg.Policies.Dir = policiesDir
	}
}

func runServe(ctx context.Context) error {
	logger, logFile, err := buildLogger(cfg.Logging)
	if err != nil {
		return fmt.Errorf("setup logger: %w", err)
	}
	if logFile != nil {
		defer logFile.Close()
	}

	store, err := storage.New(cfg.Storage.DSN)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	defer store.Close()

	policies, err := policy.LoadFromDir(cfg.Policies.Dir)
	if err != nil {
		return fmt.Errorf("load policies: %w", err)
	}

	engine := policy.NewEngine(policies, cfg.Policies.DefaultAction)

	tokenMap := make(map[string]string, len(cfg.Auth.BearerTokens))
	for _, t := range cfg.Auth.BearerTokens {
		tokenMap[t.TokenHash] = t.UserID
	}
	bearerAuth := auth.NewBearerAuth(tokenMap)

	mc := metrics.NewCollector(store.DB())
	srv := server.New(cfg.Server, store, engine, mc, bearerAuth, logger)

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.Policies.Watch {
		watcher, watchErr := policy.NewWatcher(engine, cfg.Policies.Dir, logger)
		if watchErr != nil {
			return fmt.Errorf("create policy watcher: %w", watchErr)
		}
		defer watcher.Close()
		go func() {
			if runErr := watcher.Run(ctx); runErr != nil {
				logger.Error("policy watcher stopped", "error", runErr)
			}
		}()
	}

	if cfg.Storage.Retention > 0 {
		go startRetentionPruner(ctx, store, cfg.Storage.Retention, logger)
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("starting server", "addr", cfg.Server.Addr)
		errCh <- srv.Start()
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("server exited: %w", err)
	case <-ctx.Done():
		logger.Info("shutting down server")
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(), 15*time.Second,
		)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server shutdown: %w", err)
		}
		return nil
	}
}

func buildLogger(
	cfg config.LoggingConfig,
) (*slog.Logger, *os.File, error) {
	var output io.Writer
	var logFile *os.File

	switch cfg.Output {
	case "stderr":
		output = os.Stderr
	case "stdout", "":
		output = os.Stdout
	default:
		f, err := os.OpenFile(
			cfg.Output,
			os.O_CREATE|os.O_APPEND|os.O_WRONLY,
			0644,
		)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"open log file %q: %w", cfg.Output, err,
			)
		}
		output = f
		logFile = f
	}

	level := parseLogLevel(cfg.Level)
	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	switch cfg.Format {
	case "text":
		handler = slog.NewTextHandler(output, opts)
	default:
		handler = slog.NewJSONHandler(output, opts)
	}

	return slog.New(handler), logFile, nil
}

func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func startRetentionPruner(
	ctx context.Context,
	store *storage.Store,
	retention time.Duration,
	logger *slog.Logger,
) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			before := time.Now().Add(-retention)
			count, err := store.PruneOldEvents(ctx, before)
			if err != nil {
				logger.Error("retention prune failed", "error", err)
				continue
			}
			if count > 0 {
				logger.Info("pruned old events",
					"deleted", count,
					"older_than", before.Format(time.RFC3339),
				)
			}
		}
	}
}
