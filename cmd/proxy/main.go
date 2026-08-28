// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Command proxy is the Hoplock Proxy SSH proxy daemon.
//
// It loads its bootstrap configuration, builds the management client, the
// authentication planes, and the proxy engine, and serves SSH until it is
// signalled. Every decision it enforces is made by Hoplock Control
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
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/config"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/logging"
	"github.com/hoplock/proxy/internal/proxy"
	"github.com/hoplock/proxy/internal/relay"
	"github.com/hoplock/proxy/internal/routing"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `proxy — Hoplock Proxy SSH proxy daemon

Usage:
  proxy [flags]

Flags:
  -config string
        path to the YAML bootstrap config (see config.example.yaml)
  -version
        print the version and exit
`

func main() {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }

	configPath := fs.String("config", "", "path to the YAML bootstrap config")
	showVersion := fs.Bool("version", false, "print the version and exit")

	// Parse cannot fail here: flag.ExitOnError exits on bad input.
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("proxy %s\n", version)
		return
	}

	logger := log.New(os.Stderr, "", log.LstdFlags|log.LUTC)
	if err := run(*configPath, logger); err != nil {
		logger.Printf("proxy: %v", err)
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

	hostKey, err := loadHostKey(cfg.Proxy.HostKeyPath)
	if err != nil {
		return err
	}

	rest, err := control.NewRESTClient(control.Options{
		BaseURL: cfg.Control.BaseURL,
		Token:   cfg.Control.Token,
	})
	if err != nil {
		return err
	}

	// The caching client reuses only decisions the server authorised, and only
	// while the revocation stream below is being heard (PLAN §6.4). The two are
	// built together on purpose: without the stream the cache is stale by
	// definition and serves nothing, which is the fail-closed outcome but a
	// confusing one to debug if the subscription was simply forgotten.
	cache := control.NewCachingClient(rest, control.CacheOptions{
		MaxTTL:     cfg.Control.Cache.MaxTTL,
		StaleAfter: cfg.Control.Cache.StaleAfter,
		Logger:     logger,
	})

	userAuth, err := user.NewFromConfig(cfg.Auth.User, user.Options{Client: cache, Logger: logger})
	if err != nil {
		return err
	}
	// The telemetry pipeline is built before the credential plane and the engine:
	// every session records into it, and it is closed after the engine stops serving: the
	// last session's records are shipped rather than abandoned, and whatever
	// still cannot be delivered lands in the disk buffer for the next run
	// (PLAN §7, D8). It ships to the REST client rather than the caching one —
	// there is nothing to cache about a log record, and the cache's stale-mode
	// rules are about decisions.
	recorder, err := logging.New(logging.Options{
		Client:          rest,
		BatchSize:       cfg.Logging.BatchSize,
		FlushInterval:   cfg.Logging.FlushInterval,
		QueueSize:       cfg.Logging.QueueSize,
		BufferDir:       cfg.Logging.BufferDir,
		SendTimeout:     cfg.Logging.SendTimeout,
		RetryMin:        cfg.Logging.RetryMin,
		RetryMax:        cfg.Logging.RetryMax,
		MaxPayloadBytes: cfg.Logging.MaxPayloadBytes,
		Logf:            logger.Printf,
	})
	if err != nil {
		return err
	}
	if cfg.Logging.BufferDir == "" {
		logger.Printf("proxy: no logging.buffer_dir configured; records are lost if Hoplock Control is unreachable")
	}

	targetAuth, err := target.NewFromConfig(cfg.Auth.Target, target.Options{
		ProxyID: cfg.Proxy.ID,
		Logger:  logger,
		// The device method's account-mapping event is load-bearing rather than
		// informational (PLAN §5.3): on a platform whose administrator names are
		// too short to carry a login, it is the ONLY place the account is tied
		// to a person. So the credential plane is handed the telemetry pipeline
		// and refuses such a route when there is nowhere at all to put the
		// event — which is also why the pipeline is now built before it.
		Events: recorder.DeviceSink(),
	})
	if err != nil {
		return err
	}
	// The ephemeral method's orphan reaper is background work with a lifetime,
	// so the credential plane gets started and stopped rather than only built.
	// Stopping it is what keeps a shutdown from being indistinguishable from
	// the crash the reaper exists to clean up after (PLAN §5.1).
	if lifecycle, ok := targetAuth.(target.Lifecycle); ok {
		lifecycle.Start(ctx)
		defer func() { _ = lifecycle.Close() }()
	}
	resolver, err := routing.NewResolver(routing.ResolverOptions{
		Client:            cache,
		DefaultTargetPort: cfg.Dial.DefaultTargetPort,
		Logger:            logger,
	})
	if err != nil {
		return err
	}

	// The chain identity is this proxy's own key, presented to other proxies
	// (D11). It is loaded even when nothing is chained today, so a
	// misconfigured path fails at startup rather than at the first next-hop
	// route a user happens to be given.
	hopSigner, err := loadChainIdentity(cfg.Chain)
	if err != nil {
		return err
	}

	// The relay hub is the upstream half: it holds registrations open for
	// proxies that cannot be dialled, and the engine opens sessions over them.
	hub, hubListener, err := startRelayHub(cfg, hostKey, logger)
	if err != nil {
		return err
	}
	var hubDone chan struct{}
	if hub != nil {
		hubDone = make(chan struct{})
		go func() {
			defer close(hubDone)
			if err := hub.Serve(ctx, hubListener); err != nil {
				logger.Printf("proxy: relay registrations stopped: %v", err)
			}
		}()
		logger.Printf("proxy: accepting relay registrations on %s", hubListener.Addr())
	}

	server, err := proxy.New(proxy.Options{
		HostKey:         hostKey,
		Authenticator:   userAuth,
		Resolver:        resolver,
		TargetAuth:      targetAuth,
		Client:          cache,
		ProxyID:         cfg.Proxy.ID,
		TargetDelimiter: cfg.Routing.TargetDelimiter,
		HopSigner:       hopSigner,
		RelayOpener:     relayOpener(hub),
		MaxHops:         cfg.Chain.MaxHops,
		DialTimeout:     cfg.Dial.DialTimeout,
		Recorder:        recorder,
		Logger:          logger,
	})
	if err != nil {
		return err
	}

	// The registrar is the downstream half: this proxy's outbound registration
	// with the proxy above it, over which that proxy sends sessions here
	// without any inbound rule (D11). Sessions arrive as connections and are
	// served by the same engine as any other.
	registrarDone, err := startRelayRegistrar(ctx, cfg, hopSigner, server, logger)
	if err != nil {
		return err
	}

	// The proxy is the session registry: the stream's kills land on live
	// sessions, which is what makes a cached decision safe to hold.
	stream := control.NewRevocationStream(rest, cache, server, control.StreamOptions{Logger: logger})
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		if err := stream.Subscribe(ctx, cfg.Proxy.ID); err != nil {
			// Subscribe only returns for failures a retry cannot fix (this
			// proxy's own credential was rejected). Cached decisions stop
			// being served on their own; live sessions are left alone.
			logger.Printf("proxy: revocation stream stopped: %v", err)
		}
	}()

	listener, err := net.Listen("tcp", cfg.Proxy.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Proxy.ListenAddr, err)
	}
	logger.Printf("proxy %s: listening on %s as %s, management %s, target auth %s",
		version, listener.Addr(), cfg.Proxy.ID, cfg.Control.BaseURL, targetAuth.Name())

	serveErr := server.Serve(ctx, listener)
	closeRecorder(recorder, logger)
	<-streamDone
	if registrarDone != nil {
		<-registrarDone
	}
	if hubDone != nil {
		<-hubDone
	}
	logger.Printf("proxy: stopped")
	return serveErr
}

// closeRecorder ships what the last sessions queued.
//
// It runs on a fresh context rather than the server's, which is already
// cancelled by the time Serve returns: shutting down is exactly when the
// remaining records matter, and inheriting a cancelled context would abandon
// them to the disk buffer for no reason.
func closeRecorder(recorder *logging.Shipper, logger *log.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), logShutdownTimeout)
	defer cancel()
	if err := recorder.Close(ctx); err != nil {
		logger.Printf("proxy: telemetry not fully shipped on shutdown: %v", err)
	}
}

// logShutdownTimeout bounds the final telemetry flush.
const logShutdownTimeout = 10 * time.Second

// loadHostKey reads the proxy's own SSH host key, the identity every client
// pins the proxy by.
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

// loadChainIdentity loads the key this proxy presents to other proxies, and the
// certificate for it when the fleet uses a CA. Nil means this proxy does not
// chain, which the engine reports as an outage on a next-hop route rather than
// as a denial.
func loadChainIdentity(cfg config.Chain) (ssh.Signer, error) {
	if cfg.IdentityKeyPath == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(cfg.IdentityKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read chain identity key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("parse chain identity key %q: %w", cfg.IdentityKeyPath, err)
	}
	if cfg.IdentityCertPath == "" {
		return signer, nil
	}
	certBytes, err := os.ReadFile(cfg.IdentityCertPath)
	if err != nil {
		return nil, fmt.Errorf("read chain identity certificate: %w", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, fmt.Errorf("parse chain identity certificate %q: %w", cfg.IdentityCertPath, err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("chain identity certificate %q is a plain public key", cfg.IdentityCertPath)
	}
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, fmt.Errorf("chain identity certificate %q does not match the key: %w", cfg.IdentityCertPath, err)
	}
	return certSigner, nil
}

// startRelayHub builds the registration listener, when the topology makes this
// proxy a relay hub.
func startRelayHub(cfg *config.Config, hostKey ssh.Signer, logger *log.Logger) (*relay.Hub, net.Listener, error) {
	if !cfg.Chain.AcceptsRegistrations() {
		return nil, nil, nil
	}
	authorizer, err := relay.NewAuthorizer(relay.AuthorizerOptions{
		AuthorizedKeysPath: cfg.Chain.Accept.AuthorizedKeysPath,
		TrustedCAPath:      cfg.Chain.Accept.TrustedCAPath,
	})
	if err != nil {
		return nil, nil, err
	}
	// The registration listener may present its own key, but the proxy's host
	// key is the same identity from a registering proxy's point of view, so it
	// is the default rather than a second thing to rotate.
	listenerKey := hostKey
	if path := cfg.Chain.Accept.HostKeyPath; path != "" {
		listenerKey, err = loadHostKey(path)
		if err != nil {
			return nil, nil, err
		}
	}
	hub, err := relay.NewHub(relay.HubOptions{
		HostKey:           listenerKey,
		Authorizer:        authorizer,
		KeepaliveInterval: cfg.Chain.Accept.KeepaliveInterval,
		Logger:            logger,
	})
	if err != nil {
		return nil, nil, err
	}
	l, err := net.Listen("tcp", cfg.Chain.Accept.ListenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen for relay registrations on %s: %w", cfg.Chain.Accept.ListenAddr, err)
	}
	return hub, l, nil
}

// startRelayRegistrar opens this proxy's outbound registration with its
// upstream, when it has one.
func startRelayRegistrar(ctx context.Context, cfg *config.Config, signer ssh.Signer, server *proxy.Server, logger *log.Logger) (chan struct{}, error) {
	if !cfg.Chain.Registers() {
		return nil, nil
	}
	hostKey, err := loadPublicKey(cfg.Chain.Upstream.HostKeyPath)
	if err != nil {
		return nil, err
	}
	registrar, err := relay.NewRegistrar(relay.RegistrarOptions{
		UpstreamAddr:      cfg.Chain.Upstream.Address,
		ProxyID:           cfg.Proxy.ID,
		Signer:            signer,
		HostKeyCallback:   ssh.FixedHostKey(hostKey),
		Handle:            server.ServeConn,
		DialTimeout:       cfg.Chain.Upstream.DialTimeout,
		KeepaliveInterval: cfg.Chain.Upstream.KeepaliveInterval,
		MinBackoff:        cfg.Chain.Upstream.MinBackoff,
		MaxBackoff:        cfg.Chain.Upstream.MaxBackoff,
		Logger:            logger,
	})
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := registrar.Run(ctx); err != nil {
			// Run only returns for failures a retry cannot fix: this proxy's
			// own key or the upstream's host key. Sessions already flowing are
			// left alone; new relay hops to this proxy simply stop arriving.
			logger.Printf("proxy: relay registration stopped: %v", err)
		}
	}()
	logger.Printf("proxy: registering a relay with %s as %s", cfg.Chain.Upstream.Address, cfg.Proxy.ID)
	return done, nil
}

// relayOpener adapts the hub to the engine's interface, keeping a nil hub a
// nil interface: a typed nil would look like a hub that has no registrations
// rather than a proxy that hosts none.
func relayOpener(hub *relay.Hub) proxy.RelayOpener {
	if hub == nil {
		return nil
	}
	return hub
}

// loadPublicKey reads one OpenSSH-format public key, used for the upstream's
// host key. Fleet keys are known at deployment time, so there is no
// trust-on-first-use here — that is for targets (D7), not for proxies.
func loadPublicKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse public key %q: %w", path, err)
	}
	return key, nil
}
