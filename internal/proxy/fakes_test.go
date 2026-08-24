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
	"github.com/hoplock/proxy/internal/logging"
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
	batchRecords   []control.LogRecord
	prioRecords    []control.LogRecord
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

func (c *fakeClient) IngestLogBatch(_ context.Context, req *control.LogBatchRequest) (*control.LogBatchResponse, error) {
	c.mu.Lock()
	c.batchRecords = append(c.batchRecords, req.Records...)
	c.mu.Unlock()
	return &control.LogBatchResponse{Accepted: len(req.Records)}, nil
}

func (c *fakeClient) IngestPriorityLog(_ context.Context, req *control.LogPriorityRequest) (*control.LogPriorityResponse, error) {
	c.mu.Lock()
	c.prioRecords = append(c.prioRecords, req.Record)
	c.mu.Unlock()
	return &control.LogPriorityResponse{Accepted: true, ReceiptID: "receipt"}, nil
}

// records is everything delivered on either path, batch records first. The
// priority path is separate so a test can assert not just that a record exists
// but that it did not wait in a batch (D8).
func (c *fakeClient) records() []control.LogRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]control.LogRecord, 0, len(c.batchRecords)+len(c.prioRecords))
	out = append(out, c.batchRecords...)
	out = append(out, c.prioRecords...)
	return out
}

// priorityRecords is what took the immediate path.
func (c *fakeClient) priorityRecords() []control.LogRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]control.LogRecord(nil), c.prioRecords...)
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
	// permittedRequests is the in-channel request policy (D5a axis 2). Nil is
	// the contract's absent value: not policed, which is what a v1 server
	// meant.
	permittedRequests *control.RequestPolicy
	// permittedForwards is the forwarding destination policy (D5a axis 3a).
	// Nil is not policed.
	permittedForwards *control.ForwardPolicy
	// permittedGlobalRequests is the connection-level request policy (D5a
	// axis 3b). Nil relays everything.
	permittedGlobalRequests *control.GlobalRequestPolicy
	// filterPolicy is the connection's command policy (PLAN §6.3). Nil means
	// an empty blacklist, which filters nothing.
	filterPolicy *control.FilterPolicy
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
	// targetAuth replaces the credential plane. Nil is the static-key
	// placeholder, which is what most tests want: they are about the engine,
	// not about which credential it dials with.
	targetAuth target.TargetAuthenticator
	// options adjusts the engine options before the server is built, for the
	// chaining tests: a hop identity, a relay opener, a hop cap.
	options func(*Options)
}

// harness is a running proxy with a target behind it and an SSH client in front.
type harness struct {
	t      *testing.T
	target *sshtest.Target
	client *fakeClient
	server *Server
	addr   string
	logs   *syncBuffer
	// shipper is the telemetry pipeline the engine records into (PLAN §7). It
	// is a real one, wired to fakeClient, so a test asserting "the record
	// exists" is asserting about the same path production uses.
	shipper *logging.Shipper
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
	filterPolicy := control.FilterPolicy{Mode: control.FilterModeBlacklist}
	if opts.filterPolicy != nil {
		filterPolicy = *opts.filterPolicy
	}

	client := &fakeClient{hostKey: opts.hostKey}
	client.authorize = opts.authorize
	if client.authorize == nil {
		client.authorize = func(*control.AuthorizeRequest) (*control.AuthorizeResponse, error) {
			return &control.AuthorizeResponse{
				RouteType:               routeType,
				Target:                  host,
				TargetPort:              port,
				Permissions:             "testGroup",
				PermittedChannels:       permitted,
				PermittedRequests:       opts.permittedRequests,
				PermittedForwards:       opts.permittedForwards,
				PermittedGlobalRequests: opts.permittedGlobalRequests,
				FilterPolicy:            filterPolicy,
				DecisionID:              "decision-1",
			}, nil
		}
	}

	resolver, err := routing.NewResolver(routing.ResolverOptions{Client: client})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	targetAuth := opts.targetAuth
	if targetAuth == nil {
		staticKey, err := target.NewStaticKeyAuthenticator(target.StaticKeyOptions{Signer: sshtest.MustGenerateSigner()})
		if err != nil {
			t.Fatalf("NewStaticKeyAuthenticator: %v", err)
		}
		targetAuth = staticKey
	}
	userAuth, err := user.NewCertAuthenticator(user.Options{Client: client})
	if err != nil {
		t.Fatalf("NewCertAuthenticator: %v", err)
	}

	logs := &syncBuffer{}
	// A long flush interval on purpose: a test that sees a record on the
	// priority path saw it because it was critical, not because a tick
	// happened to fire.
	shipper, err := logging.New(logging.Options{
		Client:        client,
		BatchSize:     testBatchSize,
		FlushInterval: time.Minute,
		BufferDir:     t.TempDir(),
		Logf:          logs.logger().Printf,
	})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shipper.Close(ctx)
	})
	engineOpts := Options{
		HostKey:         sshtest.MustGenerateSigner(),
		Authenticator:   userAuth,
		Resolver:        resolver,
		TargetAuth:      targetAuth,
		Client:          client,
		ProxyID:         testProxyID,
		TargetDelimiter: testDelimiter,
		DialTimeout:     2 * time.Second,
		Logger:          logs.logger(),
		Recorder:        shipper,
		NewSessionID:    func() string { return testSessionID },
	}
	if opts.options != nil {
		opts.options(&engineOpts)
	}
	server, err := New(engineOpts)
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
		t:       t,
		target:  tgt,
		client:  client,
		server:  server,
		addr:    listener.Addr().String(),
		logs:    logs,
		shipper: shipper,
	}
}

// testBatchSize keeps a batch small enough that an ordinary session fills one
// without the test having to flush, and large enough that filling one is not
// the same thing as recording a single event.
const testBatchSize = 8

// flushRecords delivers everything the session queued, so a test can assert on
// the whole record rather than on whatever a tick happened to have sent.
func (h *harness) flushRecords() {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.shipper.Flush(ctx); err != nil {
		h.t.Fatalf("flush telemetry: %v", err)
	}
}

// records is every record delivered so far, flushing first.
func (h *harness) records() []control.LogRecord {
	h.t.Helper()
	h.flushRecords()
	return h.client.records()
}

// awaitRecord waits for a record matching want, flushing on each attempt. It
// exists for the capture points that finish on their own goroutine — a stream
// inspector reassembling a line, a channel closing — where the client call has
// already returned.
func (h *harness) awaitRecord(want func(control.LogRecord) bool) (control.LogRecord, bool) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, rec := range h.records() {
			if want(rec) {
				return rec, true
			}
		}
		if time.Now().After(deadline) {
			return control.LogRecord{}, false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// recordedOnPriorityPath reports whether a record reached Hoplock Control on
// the dedicated priority endpoint rather than inside a batch (D8).
func recordedOnPriorityPath(h *harness, recordID string) bool {
	h.t.Helper()
	for _, rec := range h.client.priorityRecords() {
		if rec.RecordID == recordID {
			return true
		}
	}
	return false
}

// recordOfKind is the first record of a kind, or a failure.
func (h *harness) recordOfKind(kind control.LogKind) control.LogRecord {
	h.t.Helper()
	rec, ok := h.awaitRecord(func(r control.LogRecord) bool { return r.Kind == kind })
	if !ok {
		h.t.Fatalf("no %s record was produced", kind)
	}
	return rec
}

// targetHostPort is the stand-in target as a route would name it.
func (h *harness) targetHostPort() (string, int) {
	h.t.Helper()
	return h.target.Host(), h.target.Port()
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
