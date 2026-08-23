// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/sshtest"
)

// testDownstream is the id the registering (protected-zone) proxy claims.
const testDownstream = "proxy-enclave"

// testHub is a running hub with a listener in front of it.
type testHub struct {
	hub  *Hub
	addr string
	key  ssh.Signer
}

func startHub(t *testing.T, authorized map[string]ssh.PublicKey) *testHub {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "relay_authorized_keys")
	var lines []string
	for id, key := range authorized {
		lines = append(lines, fmt.Sprintf("%s %s", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), id))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write authorized keys: %v", err)
	}

	authorizer, err := NewAuthorizer(AuthorizerOptions{AuthorizedKeysPath: path})
	if err != nil {
		t.Fatalf("NewAuthorizer: %v", err)
	}
	hostKey := sshtest.MustGenerateSigner()
	hub, err := NewHub(HubOptions{
		HostKey:           hostKey,
		Authorizer:        authorizer,
		KeepaliveInterval: 50 * time.Millisecond,
		KeepaliveTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHub: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
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
		case <-time.After(5 * time.Second):
			t.Error("hub.Serve did not return")
		}
	})
	return &testHub{hub: hub, addr: l.Addr().String(), key: hostKey}
}

// echoHandler serves a relayed connection by echoing it back, which is enough
// to prove the byte stream really runs end to end.
func echoHandler(_ context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_, _ = io.Copy(conn, conn)
}

func startRegistrar(t *testing.T, h *testHub, signer ssh.Signer, opts RegistrarOptions) *Registrar {
	t.Helper()

	if opts.UpstreamAddr == "" {
		opts.UpstreamAddr = h.addr
	}
	if opts.ProxyID == "" {
		opts.ProxyID = testDownstream
	}
	opts.Signer = signer
	if opts.HostKeyCallback == nil {
		opts.HostKeyCallback = ssh.FixedHostKey(h.key.PublicKey())
	}
	if opts.Handle == nil {
		opts.Handle = echoHandler
	}
	if opts.KeepaliveInterval == 0 {
		opts.KeepaliveInterval = 50 * time.Millisecond
	}
	if opts.MinBackoff == 0 {
		opts.MinBackoff = 10 * time.Millisecond
	}
	if opts.MaxBackoff == 0 {
		opts.MaxBackoff = 20 * time.Millisecond
	}

	r, err := NewRegistrar(opts)
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Registrar.Run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Registrar.Run did not return")
		}
	})
	return r
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestRegistrationCarriesASession is the mechanism D11 exists for: the
// downstream proxy dials out, and the upstream reaches it over that connection
// without ever dialling in.
func TestRegistrationCarriesASession(t *testing.T) {
	signer := sshtest.MustGenerateSigner()
	h := startHub(t, map[string]ssh.PublicKey{testDownstream: signer.PublicKey()})
	startRegistrar(t, h, signer, RegistrarOptions{})

	waitFor(t, "the registration", func() bool { return h.hub.Registered(testDownstream) })

	conn, err := h.hub.Open(context.Background(), testDownstream)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := io.WriteString(conn, "hello"); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got, want := string(buf), "hello"; got != want {
		t.Errorf("relayed stream echoed %q, want %q", got, want)
	}
	if got := conn.RemoteAddr().String(); !strings.Contains(got, testDownstream) {
		t.Errorf("remote addr = %q, want it to name the peer proxy", got)
	}
}

// TestOpenWithoutARegistrationFails is the other half of the same rule: with no
// registration there is nothing to open, and the caller is told so rather than
// being handed something that would need dialling.
func TestOpenWithoutARegistrationFails(t *testing.T) {
	signer := sshtest.MustGenerateSigner()
	h := startHub(t, map[string]ssh.PublicKey{testDownstream: signer.PublicKey()})

	_, err := h.hub.Open(context.Background(), testDownstream)
	if !errors.Is(err, ErrNoRegistration) {
		t.Errorf("Open = %v, want ErrNoRegistration", err)
	}
}

// TestUnauthorizedProxyCannotRegister: a registration is an inbound path into
// this proxy's routing, so an unknown key must not create one.
func TestUnauthorizedProxyCannotRegister(t *testing.T) {
	authorized := sshtest.MustGenerateSigner()
	stranger := sshtest.MustGenerateSigner()
	h := startHub(t, map[string]ssh.PublicKey{testDownstream: authorized.PublicKey()})

	_, err := ssh.Dial("tcp", h.addr, &ssh.ClientConfig{
		User:            testDownstream,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(stranger)},
		HostKeyCallback: ssh.FixedHostKey(h.key.PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("an unauthorized key registered a relay")
	}
	if h.hub.Registered(testDownstream) {
		t.Error("a refused registration was recorded anyway")
	}
}

// TestAKeyCannotRegisterAsAnotherProxy is the reason the authorized-keys
// comment names the id: an authorized proxy claiming someone else's id would
// start receiving their sessions.
func TestAKeyCannotRegisterAsAnotherProxy(t *testing.T) {
	signer := sshtest.MustGenerateSigner()
	h := startHub(t, map[string]ssh.PublicKey{testDownstream: signer.PublicKey()})

	_, err := ssh.Dial("tcp", h.addr, &ssh.ClientConfig{
		User:            "proxy-someone-else",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(h.key.PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("a proxy registered under an id its key is not authorized for")
	}
	if h.hub.Registered("proxy-someone-else") {
		t.Error("the claimed id was registered anyway")
	}
}

// TestRegistrationReconnects covers the link dropping: the downstream proxy
// re-registers on its own, and a session opened afterwards works.
func TestRegistrationReconnects(t *testing.T) {
	signer := sshtest.MustGenerateSigner()
	h := startHub(t, map[string]ssh.PublicKey{testDownstream: signer.PublicKey()})
	r := startRegistrar(t, h, signer, RegistrarOptions{})

	waitFor(t, "the first registration", func() bool { return h.hub.Registered(testDownstream) })
	if !h.hub.Drop(testDownstream) {
		t.Fatal("Drop found no registration to close")
	}
	waitFor(t, "the reconnect", func() bool {
		return h.hub.Registered(testDownstream) && r.Registered()
	})

	conn, err := h.hub.Open(context.Background(), testDownstream)
	if err != nil {
		t.Fatalf("Open after the reconnect: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "again"); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got, want := string(buf), "again"; got != want {
		t.Errorf("relayed stream echoed %q, want %q", got, want)
	}
}

// TestReRegistrationReplacesThePrevious keeps one registration per id: a
// reconnect after an unnoticed network death must not leave the id pointing at
// a corpse.
func TestReRegistrationReplacesThePrevious(t *testing.T) {
	signer := sshtest.MustGenerateSigner()
	h := startHub(t, map[string]ssh.PublicKey{testDownstream: signer.PublicKey()})
	startRegistrar(t, h, signer, RegistrarOptions{})
	waitFor(t, "the first registration", func() bool { return h.hub.Registered(testDownstream) })

	startRegistrar(t, h, signer, RegistrarOptions{})
	waitFor(t, "the second registration", func() bool { return len(h.hub.Registrations()) == 1 })

	// Both registrars are live, but the hub still holds exactly one entry, and
	// it must be usable.
	conn, err := h.hub.Open(context.Background(), testDownstream)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = conn.Close()
}

// TestUnverifiedUpstreamIsFatal: the registrar gives up rather than retrying
// against a host key it does not trust, because that is either the wrong
// upstream or an impostor and neither improves with time.
func TestUnverifiedUpstreamIsFatal(t *testing.T) {
	signer := sshtest.MustGenerateSigner()
	h := startHub(t, map[string]ssh.PublicKey{testDownstream: signer.PublicKey()})

	r, err := NewRegistrar(RegistrarOptions{
		UpstreamAddr:    h.addr,
		ProxyID:         testDownstream,
		Signer:          signer,
		HostKeyCallback: ssh.FixedHostKey(sshtest.MustGenerateSigner().PublicKey()),
		Handle:          echoHandler,
		MinBackoff:      time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.Run(ctx); err == nil {
		t.Error("Run returned nil for an upstream whose host key does not match")
	}
}

// TestRegistrarRetriesATransientFailure: an upstream that is not listening yet
// is a normal state for a proxy fleet, and the registrar must keep trying.
func TestRegistrarRetriesATransientFailure(t *testing.T) {
	signer := sshtest.MustGenerateSigner()
	h := startHub(t, map[string]ssh.PublicKey{testDownstream: signer.PublicKey()})

	var (
		mu       sync.Mutex
		attempts int
	)
	startRegistrar(t, h, signer, RegistrarOptions{
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			mu.Lock()
			attempts++
			first := attempts == 1
			mu.Unlock()
			if first {
				return nil, errors.New("connection refused")
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
	})

	waitFor(t, "the retry to register", func() bool { return h.hub.Registered(testDownstream) })
	mu.Lock()
	defer mu.Unlock()
	if attempts < 2 {
		t.Errorf("registrar made %d attempts, want it to have retried", attempts)
	}
}

// TestAuthorizerRequiresAnIDComment: a key with no comment names no proxy id,
// so it could register as any of them. That fails at load time, not at the
// first registration.
func TestAuthorizerRequiresAnIDComment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys")
	key := sshtest.MustGenerateSigner().PublicKey()
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(key), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := NewAuthorizer(AuthorizerOptions{AuthorizedKeysPath: path}); err == nil {
		t.Error("NewAuthorizer accepted a key with no proxy id comment")
	}
	if _, err := NewAuthorizer(AuthorizerOptions{}); err == nil {
		t.Error("NewAuthorizer accepted a hub that trusts nothing")
	}
}

// TestCertificateRegistration covers the other trust source: a certificate
// signed by the fleet CA, naming the proxy id as a principal.
func TestCertificateRegistration(t *testing.T) {
	ca := sshtest.MustGenerateSigner()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pub")
	if err := os.WriteFile(caPath, ssh.MarshalAuthorizedKey(ca.PublicKey()), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	authorizer, err := NewAuthorizer(AuthorizerOptions{TrustedCAPath: caPath})
	if err != nil {
		t.Fatalf("NewAuthorizer: %v", err)
	}

	signer := sshtest.MustGenerateSigner()
	cert := &ssh.Certificate{
		Key:             signer.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           testDownstream,
		ValidPrincipals: []string{testDownstream},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := cert.SignCert(zeroReader{}, ca); err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		t.Fatalf("NewCertSigner: %v", err)
	}

	hostKey := sshtest.MustGenerateSigner()
	hub, err := NewHub(HubOptions{HostKey: hostKey, Authorizer: authorizer, KeepaliveInterval: -1})
	if err != nil {
		t.Fatalf("NewHub: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = hub.Serve(ctx, l) }()

	client, err := ssh.Dial("tcp", l.Addr().String(), &ssh.ClientConfig{
		User:            testDownstream,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("register with a certificate: %v", err)
	}
	defer func() { _ = client.Close() }()
	waitFor(t, "the certificate registration", func() bool { return hub.Registered(testDownstream) })

	// The same certificate may not claim an id it does not name.
	wrong, err := ssh.Dial("tcp", l.Addr().String(), &ssh.ClientConfig{
		User:            "proxy-elsewhere",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		_ = wrong.Close()
		t.Error("a certificate registered under a principal it does not carry")
	}
}

// zeroReader is a deterministic source for signing a test certificate; ed25519
// signing does not consume it.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
