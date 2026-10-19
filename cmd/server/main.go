// Command server runs the banner fingerprint service.
//
// Subcommands (the binary is the only executable inside the runtime image, so
// the container HEALTHCHECK uses it as its own probe):
//
//	server              run the HTTP service (default)
//	server healthcheck  GET http://127.0.0.1:$PORT/health, exit 0 on 200
//	server version      print the build version injected at link time
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/esp-oss/banner-fingerprint/internal/api"
	"github.com/esp-oss/banner-fingerprint/internal/config"
	"github.com/esp-oss/banner-fingerprint/internal/engine"
	"github.com/esp-oss/banner-fingerprint/rules"
)

// version is overridden at build time:
//
//	-ldflags "-X main.version=1.2.3"
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "server: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	sub := "serve"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "serve", "server":
		return serve()
	case "healthcheck":
		return healthcheck()
	case "version", "-v", "--version":
		fmt.Println(version)
		return nil
	default:
		return fmt.Errorf("unknown subcommand %q (want serve|healthcheck|version)", sub)
	}
}

func serve() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(log)

	loaded, source, err := loadRules(cfg)
	if err != nil {
		return err
	}
	eng, err := engine.New(loaded, source)
	if err != nil {
		return err
	}

	handler := api.New(eng, api.Config{
		MaxBatch:     cfg.MaxBatch,
		MaxBodyBytes: cfg.MaxBodyBytes,
		Workers:      cfg.Workers,
		Version:      version,
		RulesSource:  source,
		Logger:       log,
	})

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	log.Info("starting",
		"addr", cfg.Addr,
		"version", version,
		"rules", eng.Rules(),
		"rules_source", source,
		"max_batch", cfg.MaxBatch,
		"max_body_bytes", cfg.MaxBodyBytes,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errs := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
			return
		}
		errs <- nil
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down", "grace", "10s")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	log.Info("stopped")
	return nil
}

// loadRules prefers an explicit directory (bind mount) and falls back to the rule
// set embedded in the binary. The embedded path is what lets the container run on
// a scratch filesystem with no volumes at all.
func loadRules(cfg config.Config) ([]*engine.Rule, string, error) {
	if cfg.RulesDir != "" {
		loaded, desc, err := engine.Load(os.DirFS(cfg.RulesDir))
		if err != nil {
			return nil, "", fmt.Errorf("rules from %s: %w", cfg.RulesDir, err)
		}
		return loaded, "dir:" + cfg.RulesDir + " " + desc, nil
	}
	loaded, desc, err := engine.Load(rules.Embedded)
	if err != nil {
		return nil, "", fmt.Errorf("embedded rules: %w", err)
	}
	return loaded, "embedded " + desc, nil
}

// healthcheck probes the local service. It exists because the runtime image is
// scratch: no shell, no curl, no wget. The probe is therefore the binary itself,
// which also guarantees the probe tests the same code path the service serves.
func healthcheck() error {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	url := fmt.Sprintf("http://127.0.0.1:%s/health", port)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("health probe %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health probe %s: status %d", url, resp.StatusCode)
	}
	return nil
}
