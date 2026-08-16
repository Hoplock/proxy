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

	"github.com/mauroasilva/securecommandproxy/internal/auth/target"
	"github.com/mauroasilva/securecommandproxy/internal/auth/user"
	"github.com/mauroasilva/securecommandproxy/internal/config"
	"github.com/mauroasilva/securecommandproxy/internal/mgmt"
	"github.com/mauroasilva/securecommandproxy/internal/proxy"
	"github.com/mauroasilva/securecommandproxy/internal/routing"
	"github.com/mauroasilva/securecommandproxy/internal/sshtest"
)

// This file is the phase's end-to-end test: a real SSH client, a real bastion,
// a real target, and the real management contract spoken over HTTP to the mock
// server in this package.
//
// It lives here rather than in internal/proxy because the mock is a main
// package and cannot be imported. That is the reason the arrangement looks
// inside out: the engine's own tests use a fake management client to script
// decisions, and this one proves the same engine works against the contract as
// it is actually served.

const e2eSessionID = "sess-e2e"

// e2eStack is a bastion wired to the mock management server, with a stand-in
// target behind it.
type e2eStack struct {
	mock     *mock
	target   *sshtest.Target
	proxy    *proxy.Server
	addr     string
	clientKe ssh.Signer
}

// startE2E builds the whole path: fixtures naming this test's key and target,
// the mock server, the real management client, the authentication planes, and
// the proxy.
func startE2E(t *testing.T, permittedChannels []string) *e2eStack {
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

	clientKey, err := sshtest.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}

	fx := &fixtures{
		BastionToken: "e2e-token",
		Users: []fixtureUser{{
			Login: "alice",
			Identity: fixtureIdentity{
				Subject: "alice@example.com",
				Source:  "fixture",
				Groups:  []string{"engineering"},
			},
			KeyFingerprints: []string{ssh.FingerprintSHA256(clientKey.PublicKey())},
		}},
		Routes: []fixtureRoute{{
			Login:             "alice",
			Target:            tgt.Host(),
			RouteType:         string(mgmt.RouteTypeDirect),
			TargetPort:        tgt.Port(),
			Permissions:       "deployGroup",
			PermittedChannels: permittedChannels,
			FilterPolicy:      fixtureFilterPolicy{Mode: string(mgmt.FilterModeBlacklist)},
		}},
		HostKeys: fixtureHostKeys{Decision: string(mgmt.HostKeyAccept)},
	}
	m := startMock(t, fx, serverOptions{})

	userAuth, err := user.NewFromConfig(
		config.UserAuth{Methods: []string{string(mgmt.AuthMethodCert)}},
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
	server, err := proxy.New(proxy.Options{
		HostKey:         sshtest.MustGenerateSigner(),
		Authenticator:   userAuth,
		Resolver:        resolver,
		TargetAuth:      targetAuth,
		Client:          m.client,
		BastionID:       "bastion-e2e",
		TargetDelimiter: config.DefaultTargetDelimiter,
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

	return &e2eStack{mock: m, target: tgt, proxy: server, addr: listener.Addr().String(), clientKe: clientKey}
}

// dial connects to the bastion the way a user's SSH client would, with the
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
		t.Fatalf("dial the bastion: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestEndToEndDirectRoute is the phase's acceptance criterion: a user
// authenticates to the bastion, is authorized to a direct target by the real
// management contract, runs a command, and gets its output and exit status.
func TestEndToEndDirectRoute(t *testing.T) {
	stack := startE2E(t, []string{"session"})
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
		resp, err := stack.mock.client.ReportHostKey(context.Background(), &mgmt.HostKeyReportRequest{
			Target:     stack.target.Host(),
			TargetPort: stack.target.Port(),
			HostKey: mgmt.PublicKeyMaterial{
				Type:        stack.target.HostKey().Type(),
				Fingerprint: ssh.FingerprintSHA256(stack.target.HostKey()),
			},
			Conn: testConn(),
		})
		if err != nil {
			t.Fatalf("ReportHostKey: %v", err)
		}
		if !resp.Known {
			t.Error("the target's host key is unknown to the management server; the proxy did not report it")
		}
	})
}

// TestEndToEndChannelDenial checks the allow-list against the real contract: a
// route that permits nothing refuses the session it was asked for, and says so
// in the generic terms a denial is allowed (PLAN §4.3).
func TestEndToEndChannelDenial(t *testing.T) {
	stack := startE2E(t, []string{})
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
	stack := startE2E(t, []string{"session"})

	client, err := ssh.Dial("tcp", stack.addr, &ssh.ClientConfig{
		User:            "alice" + config.DefaultTargetDelimiter + "forbidden.example.com",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(stack.clientKe)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial the bastion: %v", err)
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
