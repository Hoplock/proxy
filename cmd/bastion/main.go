// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Command bastion is the SecureCommandProxy SSH bastion daemon.
//
// It loads its bootstrap configuration, builds the management client, the
// authentication planes, and the proxy engine, and serves SSH until it is
// signalled. Every decision it enforces is made by the management server
// (docs/PLAN.md, D2); this binary is wiring.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"

	"github.com/mauroasilva/securecommandproxy/internal/auth/target"
	"github.com/mauroasilva/securecommandproxy/internal/auth/user"
	"github.com/mauroasilva/securecommandproxy/internal/config"
	"github.com/mauroasilva/securecommandproxy/internal/mgmt"
	"github.com/mauroasilva/securecommandproxy/internal/proxy"
	"github.com/mauroasilva/securecommandproxy/internal/routing"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `bastion — SecureCommandProxy SSH bastion daemon

Usage:
  bastion [flags]

Flags:
  -config string
        path to the YAML bootstrap config (see config.example.yaml)
  -version
        print the version and exit
`

func main() {
	fs := flag.NewFlagSet("bastion", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }

	configPath := fs.String("config", "", "path to the YAML bootstrap config")
	showVersion := fs.Bool("version", false, "print the version and exit")

	// Parse cannot fail here: flag.ExitOnError exits on bad input.
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("bastion %s\n", version)
		return
	}

	logger := log.New(os.Stderr, "", log.LstdFlags|log.LUTC)
	if err := run(*configPath, logger); err != nil {
		logger.Printf("bastion: %v", err)
		os.Exit(1)
	}
}

func run(configPath string, logger *log.Logger) error {
	if configPath == "" {
		return errors.New("-config is required")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hostKey, err := loadHostKey(cfg.Bastion.HostKeyPath)
	if err != nil {
		return err
	}

	rest, err := mgmt.NewRESTClient(mgmt.Options{
		BaseURL: cfg.Management.BaseURL,
		Token:   cfg.Management.Token,
	})
	if err != nil {
		return err
	}

	// The caching client reuses only decisions the server authorised, and only
	// while the revocation stream below is being heard (PLAN §6.4). The two are
	// built together on purpose: without the stream the cache is stale by
	// definition and serves nothing, which is the fail-closed outcome but a
	// confusing one to debug if the subscription was simply forgotten.
	cache := mgmt.NewCachingClient(rest, mgmt.CacheOptions{
		MaxTTL:     cfg.Management.Cache.MaxTTL,
		StaleAfter: cfg.Management.Cache.StaleAfter,
		Logger:     logger,
	})

	userAuth, err := user.NewFromConfig(cfg.Auth.User, user.Options{Client: cache, Logger: logger})
	if err != nil {
		return err
	}
	targetAuth, err := target.NewFromConfig(cfg.Auth.Target, target.Options{Logger: logger})
	if err != nil {
		return err
	}
	resolver, err := routing.NewResolver(routing.ResolverOptions{
		Client:            cache,
		DefaultTargetPort: cfg.Proxy.DefaultTargetPort,
		Logger:            logger,
	})
	if err != nil {
		return err
	}

	server, err := proxy.New(proxy.Options{
		HostKey:         hostKey,
		Authenticator:   userAuth,
		Resolver:        resolver,
		TargetAuth:      targetAuth,
		Client:          cache,
		BastionID:       cfg.Bastion.ID,
		TargetDelimiter: cfg.Routing.TargetDelimiter,
		DialTimeout:     cfg.Proxy.DialTimeout,
		Logger:          logger,
	})
	if err != nil {
		return err
	}

	// The proxy is the session registry: the stream's kills land on live
	// sessions, which is what makes a cached decision safe to hold.
	stream := mgmt.NewRevocationStream(rest, cache, server, mgmt.StreamOptions{Logger: logger})
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		if err := stream.Subscribe(ctx, cfg.Bastion.ID); err != nil {
			// Subscribe only returns for failures a retry cannot fix (this
			// bastion's own credential was rejected). Cached decisions stop
			// being served on their own; live sessions are left alone.
			logger.Printf("bastion: revocation stream stopped: %v", err)
		}
	}()

	listener, err := net.Listen("tcp", cfg.Bastion.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Bastion.ListenAddr, err)
	}
	logger.Printf("bastion %s: listening on %s as %s, management %s, target auth %s",
		version, listener.Addr(), cfg.Bastion.ID, cfg.Management.BaseURL, targetAuth.Name())

	serveErr := server.Serve(ctx, listener)
	<-streamDone
	logger.Printf("bastion: stopped")
	return serveErr
}

// loadHostKey reads the bastion's own SSH host key, the identity every client
// pins the bastion by.
func loadHostKey(path string) (ssh.Signer, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read host key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("parse host key %q: %w", path, err)
	}
	return signer, nil
}
