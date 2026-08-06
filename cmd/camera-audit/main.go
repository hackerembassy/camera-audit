package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"xkem.am/camera-audit/internal/audit"
	"xkem.am/camera-audit/internal/config"
	"xkem.am/camera-audit/internal/gateway"
	"xkem.am/camera-audit/internal/mqttpub"
	"xkem.am/camera-audit/internal/store"
)

func main() {
	exitCode := 0
	// Registered first so resource-cleanup defers run before a non-zero exit.
	defer func() {
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	}()
	configPath := flag.String("config", "config.yaml", "configuration file")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("load configuration", "error", err)
		os.Exit(1)
	}
	s, err := store.Open(cfg.Database)
	if err != nil {
		log.Error("open audit database", "error", err)
		os.Exit(1)
	}
	defer s.Close()
	if err := s.RecoverOpen(context.Background(), time.Now()); err != nil {
		log.Error("reconcile audit sessions after restart", "error", err)
		os.Exit(1)
	}

	manager, err := audit.New(cfg, s, log)
	if err != nil {
		log.Error("initialize audit manager", "error", err)
		os.Exit(1)
	}
	publisher, err := mqttpub.New(cfg.MQTT, log)
	if err != nil {
		log.Error("connect MQTT", "error", err)
		os.Exit(1)
	}
	defer publisher.Close()
	manager.SetObserver(publisher.Set)
	manager.SetAvailabilityObserver(publisher.SetAvailable)

	handler, err := gateway.New(cfg, manager, s, log)
	if err != nil {
		log.Error("initialize gateway", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	managerDone := make(chan struct{})
	go func() {
		defer close(managerDone)
		manager.Run(ctx)
	}()

	server := &http.Server{Addr: cfg.Listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	serverErrors := make(chan error, 1)
	go func() {
		log.Info("camera audit listening", "address", cfg.Listen, "frigate", cfg.FrigateURL)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrors <- err
		}
	}()
	select {
	case <-ctx.Done():
	case err := <-serverErrors:
		log.Error("HTTP server", "error", err)
		exitCode = 1
		stop()
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdown)
	<-managerDone
}
