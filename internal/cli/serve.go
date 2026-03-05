package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/irad100/cc-gateway/internal/auth"
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
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(cfg.Logging.Level),
	}))

	store, err := storage.New(cfg.Storage.DSN)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	defer store.Close()

	policies, err := policy.LoadFromDir(cfg.Policies.Dir)
	if err != nil {
		return fmt.Errorf("load policies: %w", err)
	}

	engine := policy.NewEngine(policies)

	tokenMap := make(map[string]string, len(cfg.Auth.BearerTokens))
	for _, t := range cfg.Auth.BearerTokens {
		tokenMap[t.TokenHash] = t.UserID
	}
	bearerAuth := auth.NewBearerAuth(tokenMap)

	srv := server.New(cfg.Server, store, engine, bearerAuth, logger)

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
