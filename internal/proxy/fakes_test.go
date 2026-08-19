// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"context"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/routing"
	"github.com/hoplock/proxy/internal/sshtest"
)

// Fixed values every test in this package shares. The session id is fixed so
// that assertions on the support reference in a failure message are exact.
const (
	testSessionID = "sess-testsession"
	testProxyID   = "proxy-test"
	testLogin     = "alice"
	testSubject   = "alice@example.com"
	testDelimiter = "#"
)

// fakeClient is Hoplock Control. It is a fake rather than the mock
// server because these tests are about the engine: every decision is a field
// the test sets, and the contract itself is exercised end to end against the
// real mock in cmd/mock-control.
type fakeClient struct {
	authorize func(*control.AuthorizeRequest) (*control.AuthorizeResponse, error)
	hostKey   func(*control.HostKeyReportRequest) (*control.HostKeyReportResponse, error)

	mu             sync.Mutex
	authorizeCalls []control.AuthorizeRequest
	hostKeyCalls   []control.HostKeyReportRequest
}

var _ control.Client = (*fakeClient)(nil)

func (c *fakeClient) AuthenticateCert(_ context.Context, req *control.AuthenticateCertRequest) (*control.AuthenticateResponse, error) {
	return &control.AuthenticateResponse{
		Status: control.AuthStatusAuthenticated,
		Identity: &control.Identity{
			Subject: testSubject,
			Login:   req.Login,
			Source:  "fixture",
			Groups:  []string{"engineering"},
		},
	}, nil
}

func (c *fakeClient) AuthenticatePassword(context.Context, *control.AuthenticatePasswordRequest) (*control.AuthenticateResponse, error) {
	return nil, denyError("AuthenticatePassword")
}

func (c *fakeClient) PollMFA(context.Context, *control.MFAPollRequest) (*control.AuthenticateResponse, error) {
	return nil, denyError("PollMFA")
}

func (c *fakeClient) Authorize(_ context.Context, req *control.AuthorizeRequest) (*control.AuthorizeResponse, error) {
	c.mu.Lock()
	c.authorizeCalls = append(c.authorizeCalls, *req)
	c.mu.Unlock()
	return c.authorize(req)
}

func (c *fakeClient) ReportHostKey(_ context.Context, req *control.HostKeyReportRequest) (*control.HostKeyReportResponse, error) {
	c.mu.Lock()
	c.hostKeyCalls = append(c.hostKeyCalls, *req)
	c.mu.Unlock()
	if c.hostKey != nil {
		return c.hostKey(req)
	}
	return &control.HostKeyReportResponse{Decision: control.HostKeyAccept, Known: false}, nil
}

func (c *fakeClient) IngestLogBatch(context.Context, *control.LogBatchRequest) (*control.LogBatchResponse, error) {
	return &control.LogBatchResponse{}, nil
}

func (c *fakeClient) IngestPriorityLog(context.Context, *control.LogPriorityRequest) (*control.LogPriorityResponse, error) {
	return &control.LogPriorityResponse{Accepted: true}, nil
}

func (c *fakeClient) hostKeyReports() []control.HostKeyReportRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]control.HostKeyReportRequest(nil), c.hostKeyCalls...)
}

func (c *fakeClient) authorizeRequests() []control.AuthorizeRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]control.AuthorizeRequest(nil), c.authorizeCalls...)
}

// denyError is a deny decision from Hoplock Control: the one error that
// may be reported to a user as a permissions answer.
func denyError(op string) error {
	return &control.APIError{Op: op, StatusCode: 401, Cause: control.ErrUnauthorized}
}

// outageError is everything else: the server was reached but could not decide.
func outageError(op string) error {
	return &control.APIError{Op: op, StatusCode: 503, Cause: control.ErrServer}
}

// harnessOptions tune one test's proxy.
type harnessOptions struct {
	// permittedChannels is the route's channel allow-list. Nil means
	// ["session"]; an explicitly empty slice denies everything.
	permittedChannels []string
	// routeType overrides the route type; empty means direct.
	routeType control.RouteType
	// authorize replaces the whole authorize behaviour.
	authorize func(*control.AuthorizeRequest) (*control.AuthorizeResponse, error)
	// hostKey replaces the host-key decision.
	hostKey func(*control.HostKeyReportRequest) (*control.HostKeyReportResponse, error)
	// targetOptions configure the stand-in target host.
	targetOptions sshtest.Options
	// noTarget starts no target at all, so the dial fails.
	noTarget bool
}

// harness is a running proxy with a target behind it and an SSH client in front.
type harness struct {
	t      *testing.T
	target *sshtest.Target
	client *fakeClient
	server *Server
	addr   string
	logs   *syncBuffer
}

func newHarness(t *testing.T, opts harnessOptions) *harness {
	t.Helper()

	var (
		tgt     *sshtest.Target
		host    = "127.0.0.1"
		port    = 1 // unroutable placeholder when there is no target
		err     error
		cleanup = func() {}
	)
	if !opts.noTarget {
		tgt, err = sshtest.StartTarget(opts.targetOptions)
		if err != nil {
			t.Fatalf("StartTarget: %v", err)
		}
		host, port = tgt.Host(), tgt.Port()
		cleanup = func() { _ = tgt.Close() }
	}
	t.Cleanup(cleanup)

	permitted := opts.permittedChannels
	if permitted == nil {
		permitted = []string{channelSession}
	}
	routeType := opts.routeType
	if routeType == "" {
		routeType = control.RouteTypeDirect
	}

	client := &fakeClient{hostKey: opts.hostKey}
	client.authorize = opts.authorize
	if client.authorize == nil {
		client.authorize = func(*control.AuthorizeRequest) (*control.AuthorizeResponse, error) {
			return &control.AuthorizeResponse{
				RouteType:         routeType,
				Target:            host,
				TargetPort:        port,
				Permissions:       "testGroup",
				PermittedChannels: permitted,
				FilterPolicy:      control.FilterPolicy{Mode: control.FilterModeBlacklist},
				DecisionID:        "decision-1",
			}, nil
		}
	}

	resolver, err := routing.NewResolver(routing.ResolverOptions{Client: client})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	targetAuth, err := target.NewStaticKeyAuthenticator(target.StaticKeyOptions{Signer: sshtest.MustGenerateSigner()})
	if err != nil {
		t.Fatalf("NewStaticKeyAuthenticator: %v", err)
	}
	userAuth, err := user.NewCertAuthenticator(user.Options{Client: client})
	if err != nil {
		t.Fatalf("NewCertAuthenticator: %v", err)
	}

	logs := &syncBuffer{}
	server, err := New(Options{
		HostKey:         sshtest.MustGenerateSigner(),
		Authenticator:   userAuth,
		Resolver:        resolver,
		TargetAuth:      targetAuth,
		Client:          client,
		ProxyID:         testProxyID,
		TargetDelimiter: testDelimiter,
		DialTimeout:     2 * time.Second,
		Logger:          logs.logger(),
		NewSessionID:    func() string { return testSessionID },
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

	return &harness{
		t:      t,
		target: tgt,
		client: client,
		server: server,
		addr:   listener.Addr().String(),
		logs:   logs,
	}
}

// dial connects an SSH client to the proxy as username.
func (h *harness) dial(username string) (*ssh.Client, error) {
	h.t.Helper()
	key, err := sshtest.GenerateSigner()
	if err != nil {
		h.t.Fatalf("GenerateSigner: %v", err)
	}
	return ssh.Dial("tcp", h.addr, &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
}

// mustDial connects or fails the test.
func (h *harness) mustDial(username string) *ssh.Client {
	h.t.Helper()
	client, err := h.dial(username)
	if err != nil {
		h.t.Fatalf("dial as %q: %v", username, err)
	}
	h.t.Cleanup(func() { _ = client.Close() })
	return client
}

// username encodes the target the way a user's client would (D1).
func (h *harness) username() string {
	return testLogin + testDelimiter + h.targetName()
}

func (h *harness) targetName() string {
	if h.target == nil {
		return "127.0.0.1"
	}
	return h.target.Host()
}

// syncBuffer collects log output from concurrent sessions.
type syncBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *syncBuffer) logger() *log.Logger { return log.New(b, "", 0) }

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}
