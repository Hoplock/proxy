// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/config"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/logging"
	"github.com/hoplock/proxy/internal/proxy"
	"github.com/hoplock/proxy/internal/routing"
	"github.com/hoplock/proxy/internal/sshtest"
)

// This file is the phase's end-to-end test: a real SSH client, a real proxy,
// a real target, and the real management contract spoken over HTTP to the mock
// server in this package.
//
// It lives here rather than in internal/proxy because the mock is a main
// package and cannot be imported. That is the reason the arrangement looks
// inside out: the engine's own tests use a fake management client to script
// decisions, and this one proves the same engine works against the contract as
// it is actually served.

const e2eSessionID = "sess-e2e"

// e2eStack is a proxy wired to the mock Hoplock Control, with a stand-in
// target behind it.
type e2eStack struct {
	mock     *mock
	target   *sshtest.Target
	proxy    *proxy.Server
	addr     string
	clientKe ssh.Signer
	// recorder is the telemetry pipeline the proxy records into, and bufferDir
	// is its local resilience buffer (PLAN §7). Both are always present: a
	// stack that did not record would prove nothing about the pipeline every
	// other test in this file exercises implicitly.
	recorder  *logging.Shipper
	bufferDir string
	// gate makes Hoplock Control unreachable on demand, for the outage test.
	gate *controlGate
}

// e2eOptions configure the stack. The zero value is the direct-route session
// every earlier phase's test wants: cert auth, a session channel, no command
// policy.
type e2eOptions struct {
	// permittedChannels is the route's channel allow-list. Nil means
	// ["session"]; an explicitly empty slice denies everything.
	permittedChannels []string
	// filterPolicy is the route's command policy. Nil means an empty
	// blacklist, which filters nothing.
	filterPolicy *fixtureFilterPolicy
	// password, when set, adds password authentication for the fixture user
	// and enables the password-mfa plane on the proxy.
	password string
	// logging adjusts the telemetry pipeline's options.
	logging func(*logging.Options)
}

// startE2E builds the whole path: fixtures naming this test's key and target,
// the mock server, the real management client, the authentication planes, and
// the proxy.
func startE2E(t *testing.T, opts e2eOptions) *e2eStack {
	t.Helper()

	permittedChannels := opts.permittedChannels
	if permittedChannels == nil {
		permittedChannels = []string{"session"}
	}
	filterPolicy := fixtureFilterPolicy{Mode: string(control.FilterModeBlacklist)}
	if opts.filterPolicy != nil {
		filterPolicy = *opts.filterPolicy
	}

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

	clientKey, err := sshtest.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}

	fx := &fixtures{
		ProxyToken: "e2e-token",
		Users: []fixtureUser{{
			Login: "alice",
			Identity: fixtureIdentity{
				Subject: "alice@example.com",
				Source:  "fixture",
				Groups:  []string{"engineering"},
			},
			KeyFingerprints: []string{ssh.FingerprintSHA256(clientKey.PublicKey())},
			Password:        opts.password,
		}},
		Routes: []fixtureRoute{{
			Login:             "alice",
			Target:            tgt.Host(),
			RouteType:         string(control.RouteTypeDirect),
			TargetPort:        tgt.Port(),
			Permissions:       "deployGroup",
			PermittedChannels: permittedChannels,
			FilterPolicy:      filterPolicy,
		}},
		HostKeys: fixtureHostKeys{Decision: string(control.HostKeyAccept)},
	}
	gate := &controlGate{}
	m := startGatedMock(t, fx, gate)

	methods := []string{string(control.AuthMethodCert)}
	if opts.password != "" {
		methods = append(methods, string(control.AuthMethodPasswordMFA))
	}
	userAuth, err := user.NewFromConfig(
		config.UserAuth{Methods: methods},
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
	// The telemetry pipeline is real, and so is its disk buffer: these tests
	// are the only place the whole path — capture point, batch, priority
	// endpoint, buffer, drain — meets the contract as it is actually served.
	bufferDir := t.TempDir()
	logOpts := logging.Options{
		Client:        m.client,
		BatchSize:     e2eBatchSize,
		FlushInterval: e2eFlushInterval,
		BufferDir:     bufferDir,
		RetryMin:      20 * time.Millisecond,
		RetryMax:      50 * time.Millisecond,
		Logf:          t.Logf,
	}
	if opts.logging != nil {
		opts.logging(&logOpts)
	}
	recorder, err := logging.New(logOpts)
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = recorder.Close(ctx)
	})

	server, err := proxy.New(proxy.Options{
		HostKey:         sshtest.MustGenerateSigner(),
		Authenticator:   userAuth,
		Resolver:        resolver,
		TargetAuth:      targetAuth,
		Client:          m.client,
		ProxyID:         "proxy-e2e",
		TargetDelimiter: config.DefaultTargetDelimiter,
		Recorder:        recorder,
		NewSessionID:    func() string { return e2eSessionID },
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, listener) }()
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

	return &e2eStack{
		mock:      m,
		target:    tgt,
		proxy:     server,
		addr:      listener.Addr().String(),
		clientKe:  clientKey,
		recorder:  recorder,
		bufferDir: bufferDir,
		gate:      gate,
	}
}

// e2eBatchSize and e2eFlushInterval are deliberately unhelpful to a test that
// wants to see a record: the batch is bigger than a short session produces and
// the interval is longer than any test runs. Anything that arrives before a
// deliberate flush arrived because it was critical (D8).
const (
	e2eBatchSize     = 64
	e2eFlushInterval = time.Minute
)

// dial connects to the proxy the way a user's SSH client would, with the
// target encoded in the username (D1).
func (s *e2eStack) dial(t *testing.T) *ssh.Client {
	t.Helper()
	client, err := ssh.Dial("tcp", s.addr, &ssh.ClientConfig{
		User:            "alice" + config.DefaultTargetDelimiter + s.target.Host(),
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(s.clientKe)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial the proxy: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestEndToEndDirectRoute is the phase's acceptance criterion: a user
// authenticates to the proxy, is authorized to a direct target by the real
// management contract, runs a command, and gets its output and exit status.
func TestEndToEndDirectRoute(t *testing.T) {
	stack := startE2E(t, e2eOptions{})
	client := stack.dial(t)

	t.Run("exec returns output and status", func(t *testing.T) {
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

	t.Run("a failing command keeps its exit status", func(t *testing.T) {
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer func() { _ = session.Close() }()

		err = session.Run("rollback")
		var exitErr *ssh.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("Run error = %v (%T), want *ssh.ExitError", err, err)
		}
		if got, want := exitErr.ExitStatus(), 3; got != want {
			t.Errorf("exit status = %d, want %d", got, want)
		}
	})

	t.Run("interactive shell exchanges data", func(t *testing.T) {
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
		if _, err := io.WriteString(stdin, "round trip\n"); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, len("round trip\n"))
		if _, err := io.ReadFull(stdout, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		if got, want := string(buf), "round trip\n"; got != want {
			t.Errorf("shell echoed %q, want %q", got, want)
		}
		_ = stdin.Close()
		if err := session.Wait(); err != nil {
			t.Errorf("Wait: %v", err)
		}
	})

	t.Run("the target host key was reported", func(t *testing.T) {
		// The mock records keys on first sighting (D7). Reporting the same key
		// again now must come back known — which it can only be if the proxy
		// reported it during the dial above.
		resp, err := stack.mock.client.ReportHostKey(context.Background(), &control.HostKeyReportRequest{
			Target:     stack.target.Host(),
			TargetPort: stack.target.Port(),
			HostKey: control.PublicKeyMaterial{
				Type:        stack.target.HostKey().Type(),
				Fingerprint: ssh.FingerprintSHA256(stack.target.HostKey()),
			},
			Conn: testConn(),
		})
		if err != nil {
			t.Fatalf("ReportHostKey: %v", err)
		}
		if !resp.Known {
			t.Error("the target's host key is unknown to Hoplock Control; the proxy did not report it")
		}
	})
}

// TestEndToEndChannelDenial checks the allow-list against the real contract: a
// route that permits nothing refuses the session it was asked for, and says so
// in the generic terms a denial is allowed (PLAN §4.3).
func TestEndToEndChannelDenial(t *testing.T) {
	stack := startE2E(t, e2eOptions{permittedChannels: []string{}})
	client := stack.dial(t)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	var stderr bytes.Buffer
	session.Stderr = &stderr
	err = session.Run("deploy")

	var exitErr *ssh.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Run error = %v (%T), want a non-zero exit rather than a dropped connection", err, err)
	}
	if !strings.Contains(stderr.String(), user.DenyMessage) {
		t.Errorf("user saw %q, want the generic denial", stderr.String())
	}
	if strings.Contains(stderr.String(), stack.target.Host()) {
		t.Errorf("denial %q names the target", stderr.String())
	}
}

// TestEndToEndUnauthorizedTarget covers a deny from the real server: the
// fixtures have no route for this target, so authorize answers 401.
func TestEndToEndUnauthorizedTarget(t *testing.T) {
	stack := startE2E(t, e2eOptions{})

	client, err := ssh.Dial("tcp", stack.addr, &ssh.ClientConfig{
		User:            "alice" + config.DefaultTargetDelimiter + "forbidden.example.com",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(stack.clientKe)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial the proxy: %v", err)
	}
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	var stderr bytes.Buffer
	session.Stderr = &stderr
	_ = session.Run("deploy")

	text := stderr.String()
	if !strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, want the generic denial", text)
	}
	if strings.Contains(text, "forbidden.example.com") {
		t.Errorf("denial %q names the target the user asked for", text)
	}
	if strings.Contains(text, e2eSessionID) {
		t.Errorf("denial %q carries a support reference; only outages do", text)
	}
}
