// Command migrate applies the schema as a controlled operation. The service
// process never runs it: this binary is invoked deliberately.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/shuntps/project_prometheus/services/core-api/internal/config"
	"github.com/shuntps/project_prometheus/services/core-api/internal/logging"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/migration"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "core-api migrate failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		return err
	}

	logger := logging.New(os.Stdout, cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	migrations, err := migration.Load()
	if err != nil {
		return err
	}

	store, err := postgres.Open(ctx, cfg.DatabaseURL, cfg.Database)
	if err != nil {
		return err
	}
	defer store.Close()

	result, err := migration.Apply(ctx, store.Unwrap(), migrations)
	if err != nil {
		return err
	}
	logger.Info("migrations applied",
		"applied", len(result.Applied),
		"current_version", result.Current,
	)
	return nil
}
