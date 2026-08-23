// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/config"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/proxy"
	"github.com/hoplock/proxy/internal/relay"
	"github.com/hoplock/proxy/internal/routing"
	"github.com/hoplock/proxy/internal/sshtest"
)

// This file is phase 0008's end-to-end test: two real proxies, a real target,
// real SSH on every leg, and the real management contract spoken over HTTP to
// the mock in this package.
//
// The two connection directions (D11) run the same test body. That is the
// point: the direction changes only how the byte stream between the proxies is
// obtained, and everything above it — authenticate, authorize, route, channel —
// is identical, which is what makes "the route decides, the proxy obeys" true
// rather than aspirational.

const (
	proxyEdge    = "proxy-a"
	proxyEnclave = "proxy-b"
	chainLogin   = "alice"
	// unreachableB is the address the edge proxy is told the enclave proxy
	// lives at in relay mode. Nothing listens there and nothing may try: if the
	// relay path is not what carried the session, the test fails.
	unreachableB = "b.no-inbound.invalid"
)

// chain is a two-hop topology: user → proxy A (nexthop) → proxy B (direct) →
// target.
type chainStack struct {
	mock      *mock
	target    *sshtest.Target
	edge      *proxy.Server
	enclave   *proxy.Server
	hub       *chainHub
	registrar *relay.Registrar
	addr      string
	userKey   ssh.Signer
}

// chainOptions varies the topology per test.
type chainOptions struct {
	// direction is the hop connection the route carries.
	direction control.HopConnection
	// maxHops caps the chain in the route. Zero leaves it uncapped.
	maxHops int
	// loop makes proxy B route back to proxy A instead of to the target.
	loop bool
	// relayProxyID overrides the proxy id a relay hop names, so a route can
	// point at a registration that does not exist.
	relayProxyID string
}

func startChain(t *testing.T, opts chainOptions) *chainStack {
	t.Helper()

	tgt, err := sshtest.StartTarget(sshtest.Options{
		Exec: func(command string) ([]byte, []byte, uint32) {
			if command == "deploy" {
				return []byte("deployed\n"), nil, 0
			}
			return nil, []byte("unknown command\n"), 3
		},
	})
	if err != nil {
		t.Fatalf("StartTarget: %v", err)
	}
	t.Cleanup(func() { _ = tgt.Close() })

	userKey := sshtest.MustGenerateSigner()
	edgeIdentity := sshtest.MustGenerateSigner()
	enclaveIdentity := sshtest.MustGenerateSigner()

	// The enclave proxy's listener exists only in dial mode. In relay mode it
	// has none at all, and the route points the edge proxy at an address that
	// cannot resolve — so a session that arrives has provably travelled over
	// the registration.
	var (
		enclaveListener net.Listener
		hopHost         = unreachableB
		hopPort         = 22
	)
	if opts.direction != control.HopConnectionRelay {
		enclaveListener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen for the enclave proxy: %v", err)
		}
		host, port, _ := net.SplitHostPort(enclaveListener.Addr().String())
		hopHost = host
		fmt.Sscanf(port, "%d", &hopPort)
	}

	nextProxyID := proxyEnclave
	if opts.relayProxyID != "" {
		nextProxyID = opts.relayProxyID
	}

	enclaveRoute := fixtureRoute{
		Login:             chainLogin,
		Target:            tgt.Host(),
		ProxyID:           proxyEnclave,
		RouteType:         string(control.RouteTypeDirect),
		TargetPort:        tgt.Port(),
		Permissions:       "deployGroup",
		PermittedChannels: []string{"session"},
		FilterPolicy:      fixtureFilterPolicy{Mode: string(control.FilterModeBlacklist)},
	}
	if opts.loop {
		// Straight back to the proxy the session came from. Neither proxy can
		// see the whole chain; the trail is what makes this detectable at all.
		enclaveRoute.RouteType = string(control.RouteTypeNextHop)
		enclaveRoute.NextHop = "127.0.0.1"
		enclaveRoute.NextProxyID = proxyEdge
		enclaveRoute.TargetPort = 22
	}

	fx := &fixtures{
		ProxyToken: "chain-token",
		Users: []fixtureUser{{
			Login: chainLogin,
			Identity: fixtureIdentity{
				Subject: "alice@example.com",
				Source:  "fixture",
				Groups:  []string{"engineering"},
			},
			KeyFingerprints: []string{ssh.FingerprintSHA256(userKey.PublicKey())},
		}},
		Proxies: []fixtureProxy{{
			ID:              proxyEdge,
			KeyFingerprints: []string{ssh.FingerprintSHA256(edgeIdentity.PublicKey())},
		}, {
			ID:              proxyEnclave,
			KeyFingerprints: []string{ssh.FingerprintSHA256(enclaveIdentity.PublicKey())},
		}},
		Routes: []fixtureRoute{{
			Login:             chainLogin,
			Target:            tgt.Host(),
			ProxyID:           proxyEdge,
			RouteType:         string(control.RouteTypeNextHop),
			NextHop:           hopHost,
			TargetPort:        hopPort,
			HopConnection:     string(opts.direction),
			NextProxyID:       nextProxyID,
			MaxHops:           opts.maxHops,
			Permissions:       "deployGroup",
			PermittedChannels: []string{"session"},
			FilterPolicy:      fixtureFilterPolicy{Mode: string(control.FilterModeBlacklist)},
		}, enclaveRoute},
		HostKeys: fixtureHostKeys{Decision: string(control.HostKeyAccept)},
	}
	m := startMock(t, fx, serverOptions{})

	stack := &chainStack{mock: m, target: tgt, userKey: userKey}

	// The relay hub lives on the edge proxy: the enclave proxy registers with
	// it, and the edge opens sessions over that registration.
	var opener proxy.RelayOpener
	if opts.direction == control.HopConnectionRelay {
		stack.hub = startChainHub(t, enclaveIdentity.PublicKey())
		opener = stack.hub.hub
	}

	stack.enclave = buildChainProxy(t, m, proxyEnclave, func(o *proxy.Options) {
		o.HopSigner = enclaveIdentity
	})
	stack.edge = buildChainProxy(t, m, proxyEdge, func(o *proxy.Options) {
		o.HopSigner = edgeIdentity
		o.RelayOpener = opener
	})

	if opts.direction == control.HopConnectionRelay {
		stack.registrar = startChainRegistrar(t, stack.hub, enclaveIdentity, stack.enclave)
	} else {
		serveChainProxy(t, stack.enclave, enclaveListener)
	}

	edgeListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the edge proxy: %v", err)
	}
	serveChainProxy(t, stack.edge, edgeListener)
	stack.addr = edgeListener.Addr().String()
	return stack
}

// buildChainProxy builds one proxy of the chain against the shared mock.
func buildChainProxy(t *testing.T, m *mock, id string, tweak func(*proxy.Options)) *proxy.Server {
	t.Helper()

	userAuth, err := user.NewFromConfig(
		config.UserAuth{Methods: []string{string(control.AuthMethodCert)}},
		user.Options{Client: m.client},
	)
	if err != nil {
		t.Fatalf("user.NewFromConfig: %v", err)
	}
	targetAuth, err := target.NewStaticKeyAuthenticator(target.StaticKeyOptions{
		Signer: sshtest.MustGenerateSigner(),
	})
	if err != nil {
		t.Fatalf("NewStaticKeyAuthenticator: %v", err)
	}
	resolver, err := routing.NewResolver(routing.ResolverOptions{Client: m.client})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	var counter atomic.Int64
	opts := proxy.Options{
		HostKey:         sshtest.MustGenerateSigner(),
		Authenticator:   userAuth,
		Resolver:        resolver,
		TargetAuth:      targetAuth,
		Client:          m.client,
		ProxyID:         id,
		TargetDelimiter: config.DefaultTargetDelimiter,
		DialTimeout:     5 * time.Second,
		NewSessionID: func() string {
			return fmt.Sprintf("sess-%s-%d", id, counter.Add(1))
		},
	}
	if tweak != nil {
		tweak(&opts)
	}
	server, err := proxy.New(opts)
	if err != nil {
		t.Fatalf("proxy.New(%s): %v", id, err)
	}
	return server
}

func serveChainProxy(t *testing.T, server *proxy.Server, l net.Listener) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return after the context ended")
		}
	})
}

// chainHub is the edge proxy's registration listener plus what a test needs to
// reach and verify it.
type chainHub struct {
	hub     *relay.Hub
	addr    string
	hostKey ssh.Signer
}

// startChainHub runs the edge proxy's registration listener, trusting exactly
// one key for exactly one proxy id.
func startChainHub(t *testing.T, enclaveKey ssh.PublicKey) *chainHub {
	t.Helper()

	path := filepath.Join(t.TempDir(), "relay_authorized_keys")
	line := fmt.Sprintf("%s %s\n", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(enclaveKey))), proxyEnclave)
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("write authorized keys: %v", err)
	}
	authorizer, err := relay.NewAuthorizer(relay.AuthorizerOptions{AuthorizedKeysPath: path})
	if err != nil {
		t.Fatalf("relay.NewAuthorizer: %v", err)
	}
	hostKey := sshtest.MustGenerateSigner()
	hub, err := relay.NewHub(relay.HubOptions{
		HostKey:           hostKey,
		Authorizer:        authorizer,
		KeepaliveInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("relay.NewHub: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for relay registrations: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- hub.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("hub.Serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("hub.Serve did not return")
		}
	})
	return &chainHub{hub: hub, addr: l.Addr().String(), hostKey: hostKey}
}

// startChainRegistrar has the enclave proxy register with the edge proxy and
// serve whatever arrives over that registration.
func startChainRegistrar(t *testing.T, hub *chainHub, identity ssh.Signer, server *proxy.Server) *relay.Registrar {
	t.Helper()

	registrar, err := relay.NewRegistrar(relay.RegistrarOptions{
		UpstreamAddr:      hub.addr,
		ProxyID:           proxyEnclave,
		Signer:            identity,
		HostKeyCallback:   ssh.FixedHostKey(hub.hostKey.PublicKey()),
		Handle:            server.ServeConn,
		KeepaliveInterval: 100 * time.Millisecond,
		MinBackoff:        10 * time.Millisecond,
		MaxBackoff:        50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("relay.NewRegistrar: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- registrar.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Registrar.Run: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Registrar.Run did not return")
		}
	})
	waitForChain(t, "the relay registration", func() bool { return hub.hub.Registered(proxyEnclave) })
	return registrar
}

func waitForChain(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// dial connects to the edge proxy the way a user's SSH client would.
func (s *chainStack) dial(t *testing.T) *ssh.Client {
	t.Helper()
	client, err := ssh.Dial("tcp", s.addr, &ssh.ClientConfig{
		User:            chainLogin + config.DefaultTargetDelimiter + s.target.Host(),
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(s.userKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial the edge proxy: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestEndToEndChain is the phase's headline claim, run in both connection
// directions: a user reaches a target through two proxies, each of which
// authenticates, authorizes, and routes on its own.
func TestEndToEndChain(t *testing.T) {
	for _, direction := range []control.HopConnection{control.HopConnectionDial, control.HopConnectionRelay} {
		t.Run(string(direction), func(t *testing.T) {
			stack := startChain(t, chainOptions{direction: direction, maxHops: 3})

			if direction == control.HopConnectionRelay {
				// The claim under test: nothing can dial the enclave proxy. If
				// the address in the route were reachable, a session arriving
				// at the target would prove nothing about the relay.
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(unreachableB, "22"), 2*time.Second)
				if err == nil {
					_ = conn.Close()
					t.Fatalf("%s is reachable; the relay test would prove nothing", unreachableB)
				}
			}

			client := stack.dial(t)

			t.Run("exec runs on the target", func(t *testing.T) {
				session, err := client.NewSession()
				if err != nil {
					t.Fatalf("NewSession: %v", err)
				}
				defer func() { _ = session.Close() }()

				var stderr bytes.Buffer
				session.Stderr = &stderr
				out, err := session.Output("deploy")
				if err != nil {
					t.Fatalf("Output: %v (stderr %q)", err, stderr.String())
				}
				if got, want := string(out), "deployed\n"; got != want {
					t.Errorf("stdout = %q, want %q", got, want)
				}
			})

			t.Run("an interactive shell exchanges data", func(t *testing.T) {
				session, err := client.NewSession()
				if err != nil {
					t.Fatalf("NewSession: %v", err)
				}
				defer func() { _ = session.Close() }()

				if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
					t.Fatalf("RequestPty: %v", err)
				}
				stdin, err := session.StdinPipe()
				if err != nil {
					t.Fatalf("StdinPipe: %v", err)
				}
				stdout, err := session.StdoutPipe()
				if err != nil {
					t.Fatalf("StdoutPipe: %v", err)
				}
				if err := session.Shell(); err != nil {
					t.Fatalf("Shell: %v", err)
				}
				if _, err := io.WriteString(stdin, "through two hops\n"); err != nil {
					t.Fatalf("write: %v", err)
				}
				buf := make([]byte, len("through two hops\n"))
				if _, err := io.ReadFull(stdout, buf); err != nil {
					t.Fatalf("read: %v", err)
				}
				if got, want := string(buf), "through two hops\n"; got != want {
					t.Errorf("shell echoed %q, want %q", got, want)
				}
				_ = stdin.Close()
				if err := session.Wait(); err != nil {
					t.Errorf("Wait: %v", err)
				}
			})

			t.Run("every hop authorized for itself", func(t *testing.T) {
				var edge, enclave *authorizeCall
				for i, call := range stack.mock.server.authorizeCalls() {
					switch call.ProxyID {
					case proxyEdge:
						edge = &stack.mock.server.authorizeCalls()[i]
					case proxyEnclave:
						enclave = &stack.mock.server.authorizeCalls()[i]
					}
				}
				if edge == nil {
					t.Fatal("the edge proxy did not call authorize")
				}
				if enclave == nil {
					t.Fatal("the enclave proxy did not call authorize; it took the decision on trust")
				}
				if len(edge.HopTrail) != 0 {
					t.Errorf("the edge proxy sent hop trail %v, want none: it is the first hop", edge.HopTrail)
				}
				if got, want := strings.Join(enclave.HopTrail, ">"), proxyEdge; got != want {
					t.Errorf("the enclave proxy sent hop trail %q, want %q", got, want)
				}
				if got, want := enclave.Target, stack.target.Host(); got != want {
					t.Errorf("the enclave proxy authorized target %q, want the final target %q", got, want)
				}
				if got, want := enclave.Subject, "alice@example.com"; got != want {
					t.Errorf("the enclave proxy authorized subject %q, want the user's %q", got, want)
				}
			})
		})
	}
}

// TestChainRelayReconnects covers the registration dropping under a live
// topology: the enclave proxy re-registers on its own, and the next session
// goes through.
func TestChainRelayReconnects(t *testing.T) {
	stack := startChain(t, chainOptions{direction: control.HopConnectionRelay})

	if !stack.hub.hub.Drop(proxyEnclave) {
		t.Fatal("Drop found no registration to close")
	}
	waitForChain(t, "the re-registration", func() bool {
		return stack.hub.hub.Registered(proxyEnclave) && stack.registrar.Registered()
	})

	client := stack.dial(t)
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	var stderr bytes.Buffer
	session.Stderr = &stderr
	out, err := session.Output("deploy")
	if err != nil {
		t.Fatalf("Output after the reconnect: %v (stderr %q)", err, stderr.String())
	}
	if got, want := string(out), "deployed\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

// TestChainRelayWithoutARegistrationIsAnOutage is D11's refusal rule end to
// end: the route names a proxy that is not registered, and the session fails as
// an outage rather than being dialled.
func TestChainRelayWithoutARegistrationIsAnOutage(t *testing.T) {
	stack := startChain(t, chainOptions{
		direction:    control.HopConnectionRelay,
		relayProxyID: "proxy-not-here",
	})

	text, status := runChainCommand(t, stack, "deploy")

	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, want an outage rather than a denial", text)
	}
	if !strings.Contains(text, "not currently connected") {
		t.Errorf("user saw %q, want it to say the next proxy is not connected", text)
	}
	if !strings.Contains(text, "sess-"+proxyEdge) {
		t.Errorf("user saw %q, want the edge proxy's session id as a support reference", text)
	}
	if status == 0 {
		t.Error("a session that never reached its target exited 0")
	}
	// The enclave proxy is registered and reachable over the relay; the route
	// named a different id, and the edge proxy refused rather than looking for
	// another way there.
	if !stack.hub.hub.Registered(proxyEnclave) {
		t.Error("the enclave registration went away; the refusal was not about the named id")
	}
}

// TestChainLoopIsRefused covers a chain that doubles back: the enclave proxy is
// routed to the edge proxy it came from, and refuses because the trail says it
// has been there.
func TestChainLoopIsRefused(t *testing.T) {
	stack := startChain(t, chainOptions{direction: control.HopConnectionDial, loop: true})

	text, status := runChainCommand(t, stack, "deploy")

	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, want an outage rather than a denial", text)
	}
	if !strings.Contains(text, "chain of proxies") {
		t.Errorf("user saw %q, want it to name the chain", text)
	}
	if !strings.Contains(text, "sess-"+proxyEnclave) {
		t.Errorf("user saw %q, want the refusing proxy's session id", text)
	}
	if status == 0 {
		t.Error("a looping chain exited 0")
	}
}

// TestChainHopLimitIsRefused covers the cap: one hop is all the route allows,
// and the edge proxy has already used it.
func TestChainHopLimitIsRefused(t *testing.T) {
	stack := startChain(t, chainOptions{direction: control.HopConnectionDial, maxHops: 1})

	text, status := runChainCommand(t, stack, "deploy")

	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, want an outage rather than a denial", text)
	}
	if !strings.Contains(text, "sess-"+proxyEdge) {
		t.Errorf("user saw %q, want the edge proxy's session id", text)
	}
	if status == 0 {
		t.Error("a chain over the hop limit exited 0")
	}
	// The chain was refused before it was built: the second hop never asked.
	for _, call := range stack.mock.server.authorizeCalls() {
		if call.ProxyID == proxyEnclave {
			t.Error("the enclave proxy was reached despite the hop limit")
		}
	}
}

// runChainCommand runs one command through the chain and returns what the user
// saw on stderr plus the exit status.
func runChainCommand(t *testing.T, stack *chainStack, command string) (string, int) {
	t.Helper()

	client := stack.dial(t)
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	var stderr bytes.Buffer
	session.Stderr = &stderr
	err = session.Run(command)

	status := 0
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		status = exitErr.ExitStatus()
	} else if err != nil {
		t.Logf("Run returned %v (%T)", err, err)
		status = -1
	}
	return stderr.String(), status
}
