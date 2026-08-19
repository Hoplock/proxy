// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Command mock-control is the reference/mock Hoplock Control used for
// development and CI (docs/PLAN.md, D3).
//
// It implements the contract in api/control.yaml from a static fixture file,
// so a proxy — or a test — gets deterministic, scriptable policy decisions
// without a real Hoplock Control. See api/README.md for the endpoints and the
// fixture format, and cmd/mock-control/fixtures.example.yaml for a worked
// example.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `mock-control — Hoplock Proxy mock Hoplock Control

Usage:
  mock-control [flags]

Flags:
  -listen string
        host:port to serve the mock Control API on (default "127.0.0.1:8080")
  -fixtures string
        path to the fixture file describing users, routes, and host-key policy
        (default "fixtures.example.yaml")
  -log-dir string
        optional directory to mirror ingested log records into as JSONL
  -version
        print the version and exit
`

// Server timeouts. The mock is only ever driven by tests and the e2e topology,
// but a hung client should not pin a connection forever.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
	shutdownTimeout   = 5 * time.Second
)

func main() {
	fs := flag.NewFlagSet("mock-control", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }

	listenAddr := fs.String("listen", "127.0.0.1:8080", "host:port to serve the mock Control API on")
	fixturesPath := fs.String("fixtures", "fixtures.example.yaml", "path to the fixture file")
	logDir := fs.String("log-dir", "", "optional directory to mirror ingested log records into")
	showVersion := fs.Bool("version", false, "print the version and exit")

	// Parse cannot fail here: flag.ExitOnError exits on bad input.
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("mock-control %s\n", version)
		return
	}

	logger := log.New(os.Stderr, "", log.LstdFlags|log.LUTC)
	if err := run(*listenAddr, *fixturesPath, *logDir, logger); err != nil {
		logger.Printf("mock-control: %v", err)
		os.Exit(1)
	}
}

// run loads the fixtures, serves until interrupted, then shuts down cleanly.
func run(listenAddr, fixturesPath, logDir string, logger *log.Logger) error {
	fx, err := loadFixtures(fixturesPath)
	if err != nil {
		return err
	}
	if logDir != "" {
		if err := os.MkdirAll(logDir, 0o750); err != nil {
			return fmt.Errorf("create log dir: %w", err)
		}
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           newServer(fx, serverOptions{LogDir: logDir, Logger: logger}).handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          logger,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Printf("mock-control %s: serving %d users and %d routes on %s (fixtures %s)",
			version, len(fx.Users), len(fx.Routes), listenAddr, fixturesPath)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
		logger.Print("mock-control: shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
}
