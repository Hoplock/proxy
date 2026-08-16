// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package user

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mauroasilva/securecommandproxy/internal/config"
	"github.com/mauroasilva/securecommandproxy/internal/identity"
	"github.com/mauroasilva/securecommandproxy/internal/mgmt"
)

// testConnMeta is the ConnMetaFunc the SSH tests use. Splitting the SSH
// username is routing's job (D1) and lands in a later phase; this stands in for
// it with the delimiter the default config uses.
func testConnMeta(conn ssh.ConnMetadata) ConnMeta {
	base := testMeta()
	login, target, found := strings.Cut(conn.User(), config.DefaultTargetDelimiter)
	base.Login = login
	if found {
		base.Target = target
	} else {
		base.Target = ""
	}
	return ConnMetaFromSSH(base, conn)
}

func newServerAuth(t *testing.T, auth UserAuthenticator) *ServerAuth {
	t.Helper()
	sa, err := NewServerAuth(ServerAuthOptions{Authenticator: auth, ConnMeta: testConnMeta})
	if err != nil {
		t.Fatalf("NewServerAuth returned error: %v", err)
	}
	return sa
}

func TestNewServerAuthRequiresItsDependencies(t *testing.T) {
	if _, err := NewServerAuth(ServerAuthOptions{ConnMeta: testConnMeta}); err == nil {
		t.Error("NewServerAuth without an authenticator = nil error, want an error")
	}
	if _, err := NewServerAuth(ServerAuthOptions{Authenticator: &stubAuthenticator{}}); err == nil {
		t.Error("NewServerAuth without a ConnMeta function = nil error, want an error")
	}
}

// TestApplyOffersOnlySupportedMethods keeps a certificate-only bastion from
// prompting users for a password that can never work.
func TestApplyOffersOnlySupportedMethods(t *testing.T) {
	client := &fakeClient{}

	for _, tt := range []struct {
		name         string
		methods      []string
		wantCert     bool
		wantPassword bool
	}{
		{name: "both", methods: config.DefaultUserAuthMethods(), wantCert: true, wantPassword: true},
		{name: "certificate only", methods: []string{MethodCert}, wantCert: true},
		{name: "password only", methods: []string{MethodPasswordMFA}, wantPassword: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewFromConfig(config.UserAuth{Methods: tt.methods}, Options{Client: client})
			if err != nil {
				t.Fatalf("NewFromConfig returned error: %v", err)
			}
			var cfg ssh.ServerConfig
			newServerAuth(t, r).Apply(&cfg)

			if got := cfg.PublicKeyCallback != nil; got != tt.wantCert {
				t.Errorf("PublicKeyCallback set = %v, want %v", got, tt.wantCert)
			}
			if got := cfg.KeyboardInteractiveCallback != nil; got != tt.wantPassword {
				t.Errorf("KeyboardInteractiveCallback set = %v, want %v", got, tt.wantPassword)
			}
			if cfg.BannerCallback == nil {
				t.Error("BannerCallback not set; the user must be told what the wait is")
			}
			if cfg.NoClientAuth {
				t.Error("NoClientAuth = true; an unauthenticated session has no identity to authorize or audit")
			}
		})
	}
}

// TestDisclosureSplit is PLAN §4.3 asserted on the exact text handed to the SSH
// layer. The two branches must stay distinguishable: a deny says nothing about
// what was wrong, an outage says plainly that it is not a permissions problem
// and carries the session id.
func TestDisclosureSplit(t *testing.T) {
	_, pub := testKey(t)
	meta := testMeta()

	tests := []struct {
		name    string
		err     error
		wantErr error
	}{
		{name: "deny", err: denyError("AuthenticateCert"), wantErr: ErrDenied},
		{name: "outage", err: transportError("AuthenticateCert"), wantErr: ErrUnavailable},
	}

	messages := make(map[string]string, len(tests))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeClient{
				certFn: func(context.Context, *mgmt.AuthenticateCertRequest) (*mgmt.AuthenticateResponse, error) {
					return nil, tt.err
				},
			}
			auth, err := NewCertAuthenticator(Options{Client: client})
			if err != nil {
				t.Fatalf("NewCertAuthenticator returned error: %v", err)
			}
			sa := newServerAuth(t, auth)

			_, err = sa.PublicKeyCallback(&stubConnMetadata{user: "alice#db01.corp.example.com"}, pub)
			if err == nil {
				t.Fatal("PublicKeyCallback = nil error, want a failure")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want errors.Is(..., %v)", err, tt.wantErr)
			}

			var bannerErr *ssh.BannerError
			if !errors.As(err, &bannerErr) {
				t.Fatalf("error type = %T, want an *ssh.BannerError so the text reaches the user", err)
			}
			messages[tt.name] = bannerErr.Message
		})
	}

	deny, outage := messages["deny"], messages["outage"]

	if deny == "" || outage == "" {
		t.Fatalf("missing messages: deny=%q outage=%q", deny, outage)
	}
	// The two must not collapse into one message.
	if strings.TrimSpace(deny) == strings.TrimSpace(outage) {
		t.Fatalf("deny and outage produced the same message %q", deny)
	}

	// A deny is an oracle if it is specific: it must name neither the login nor
	// the target, and must not hint at which was wrong.
	for _, secret := range []string{meta.Login, meta.Target, "key", "password", "certificate"} {
		if strings.Contains(strings.ToLower(deny), strings.ToLower(secret)) {
			t.Errorf("deny message %q reveals %q", deny, secret)
		}
	}
	if strings.Contains(deny, meta.SessionID) {
		t.Errorf("deny message %q carries the session id; only the outage message does", deny)
	}

	// An outage must say it is not a permissions problem, and must carry the
	// support reference.
	lower := strings.ToLower(outage)
	if !strings.Contains(lower, "not a permissions problem") {
		t.Errorf("outage message %q does not say this is not a permissions problem", outage)
	}
	if !strings.Contains(outage, meta.SessionID) {
		t.Errorf("outage message %q does not carry the session id", outage)
	}
	if strings.Contains(lower, strings.ToLower(meta.Target)) {
		t.Errorf("outage message %q names the target", outage)
	}
}

func TestFailureMessageDefaultsToOutage(t *testing.T) {
	// A caller that reached a failure path without an error must not produce
	// "access denied": "I do not know" is never safely rendered as "not allowed".
	if got := FailureMessage(nil, "sess-0001"); got == DenyMessage {
		t.Errorf("FailureMessage(nil) = %q, want the outage message", got)
	}
	if got := FailureMessage(errors.New("something else"), "sess-0001"); got == DenyMessage {
		t.Errorf("FailureMessage(unclassified) = %q, want the outage message", got)
	}
	// A raw management error classifies correctly without being translated
	// first, so a caller cannot get the disclosure wrong by forgetting to.
	if got := FailureMessage(denyError("Authorize"), "sess-0001"); got != DenyMessage {
		t.Errorf("FailureMessage(mgmt deny) = %q, want %q", got, DenyMessage)
	}
	if got := OutageMessage(""); strings.Contains(got, "Quote session id") {
		t.Errorf("OutageMessage(\"\") = %q, want no dangling support reference", got)
	}
	if got := BannerMessage(""); got == "" {
		t.Error("BannerMessage(\"\") = \"\", want a banner even without a session id")
	}
}

func TestIdentityFromPermissions(t *testing.T) {
	id := &identity.Identity{
		Subject:         "alice@example.com",
		Login:           "alice",
		DisplayName:     "Alice Example",
		Source:          "fixture",
		Principals:      []string{"alice"},
		Groups:          []string{"engineering"},
		Claims:          identity.Claims{"dept": "platform"},
		Method:          identity.MethodCert,
		AuthenticatedAt: time.Now().UTC().Truncate(time.Second),
	}

	perms, err := permissionsFor(id, testMeta())
	if err != nil {
		t.Fatalf("permissionsFor returned error: %v", err)
	}

	got, err := IdentityFromPermissions(perms)
	if err != nil {
		t.Fatalf("IdentityFromPermissions returned error: %v", err)
	}
	if got.Subject != id.Subject || got.Method != id.Method || !got.HasGroup("engineering") ||
		got.Claims.Value("dept") != "platform" || !got.AuthenticatedAt.Equal(id.AuthenticatedAt) {
		t.Errorf("round trip = %+v, want %+v", got, id)
	}
	if want := testMeta().SessionID; SessionIDFromPermissions(perms) != want {
		t.Errorf("SessionIDFromPermissions = %q, want %q", SessionIDFromPermissions(perms), want)
	}
	if got, want := perms.Extensions[ExtensionAuthMethod], string(identity.MethodCert); got != want {
		t.Errorf("auth method extension = %q, want %q", got, want)
	}

	for _, tt := range []struct {
		name  string
		perms *ssh.Permissions
	}{
		{name: "nil", perms: nil},
		{name: "no extensions", perms: &ssh.Permissions{}},
		{name: "no identity", perms: &ssh.Permissions{Extensions: map[string]string{"other": "x"}}},
		{name: "corrupt", perms: &ssh.Permissions{Extensions: map[string]string{ExtensionIdentity: "{"}}},
		{name: "incomplete", perms: &ssh.Permissions{Extensions: map[string]string{ExtensionIdentity: `{"Login":"alice"}`}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if id, err := IdentityFromPermissions(tt.perms); err == nil {
				t.Errorf("IdentityFromPermissions = %+v, want an error", id)
			}
		})
	}
}

// stubConnMetadata is the minimum ssh.ConnMetadata the callbacks touch.
type stubConnMetadata struct {
	ssh.ConnMetadata
	user string
}

func (c *stubConnMetadata) User() string          { return c.user }
func (c *stubConnMetadata) ClientVersion() []byte { return []byte("SSH-2.0-Go") }
func (c *stubConnMetadata) RemoteAddr() net.Addr  { return nil }
func (c *stubConnMetadata) LocalAddr() net.Addr   { return nil }

// --- full SSH handshake -----------------------------------------------------

// handshake runs a real SSH handshake over an in-memory pipe against sa. It is
// worth the machinery: the fallback from certificate to keyboard-interactive,
// the banner, and the MFA instruction are all behaviours of the SSH protocol
// conversation, not of the functions in isolation.
type handshake struct {
	clientErr  error
	serverConn *ssh.ServerConn
	serverErr  error
	banners    []string
}

// kbiRequest is one keyboard-interactive request as the client saw it.
type kbiRequest struct {
	instruction string
	questions   []string
}

// kbiRecorder is the client half of a keyboard-interactive exchange: it answers
// every question with the password and keeps what it was shown, which is how
// these tests see what the user would have seen.
type kbiRecorder struct {
	mu       sync.Mutex
	requests []kbiRequest
}

func (r *kbiRecorder) authMethod(password string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(_, instruction string, questions []string, _ []bool) ([]string, error) {
		r.mu.Lock()
		r.requests = append(r.requests, kbiRequest{
			instruction: instruction,
			questions:   append([]string(nil), questions...),
		})
		r.mu.Unlock()

		answers := make([]string, len(questions))
		for i := range questions {
			answers[i] = password
		}
		return answers, nil
	})
}

func (r *kbiRecorder) snapshot() []kbiRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]kbiRequest(nil), r.requests...)
}

// loopbackPair returns two connected sockets over the loopback interface.
//
// net.Pipe is not usable here: it is unbuffered and synchronous, so the SSH
// transport — which writes several packets before reading — deadlocks on it.
// x/crypto's own handshake tests use a loopback socket for the same reason.
func loopbackPair(t *testing.T) (server, client net.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer func() { _ = ln.Close() }()

	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		conn, err := ln.Accept()
		ch <- accepted{conn, err}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	a := <-ch
	if a.err != nil {
		t.Fatalf("accepting: %v", a.err)
	}

	t.Cleanup(func() {
		_ = a.conn.Close()
		_ = client.Close()
	})
	return a.conn, client
}

func runHandshake(t *testing.T, sa *ServerAuth, user string, auths []ssh.AuthMethod) *handshake {
	t.Helper()

	hostSigner, _ := testKey(t)
	serverCfg := &ssh.ServerConfig{}
	sa.Apply(serverCfg)
	serverCfg.AddHostKey(hostSigner)

	serverPipe, clientPipe := loopbackPair(t)

	h := &handshake{}
	var mu sync.Mutex

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, chans, reqs, err := ssh.NewServerConn(serverPipe, serverCfg)
		h.serverConn, h.serverErr = conn, err
		if err != nil {
			return
		}
		go ssh.DiscardRequests(reqs)
		go func() {
			for nc := range chans {
				_ = nc.Reject(ssh.Prohibited, "no channels in this phase")
			}
		}()
	}()

	clientCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		BannerCallback: func(message string) error {
			mu.Lock()
			defer mu.Unlock()
			h.banners = append(h.banners, message)
			return nil
		},
	}

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		conn, _, _, err := ssh.NewClientConn(clientPipe, "pipe", clientCfg)
		h.clientErr = err
		if conn != nil {
			_ = conn.Close()
		}
	}()

	select {
	case <-clientDone:
	case <-time.After(15 * time.Second):
		t.Fatal("SSH handshake did not finish")
	}
	_ = serverPipe.Close()
	<-serverDone

	mu.Lock()
	defer mu.Unlock()
	h.banners = append([]string(nil), h.banners...)
	return h
}

// TestHandshakeFallsBackToPasswordAndMFA is the acceptance test for this phase:
// a key that the server rejects, a fallback to keyboard-interactive, an
// out-of-band approval that the user is kept informed about, and an
// authenticated identity on the accepted connection.
func TestHandshakeFallsBackToPasswordAndMFA(t *testing.T) {
	const serverPrompt = "Approve the login request on your phone."
	var polls atomic.Int32

	_, client := newRecordingServer(t, map[string]http.HandlerFunc{
		mgmt.PathAuthenticateCert: func(w http.ResponseWriter, _ *http.Request) {
			writeDeny(t, w, "unknown_key", "no")
		},
		mgmt.PathAuthenticatePassword: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, mgmt.AuthenticateResponse{
				Status: mgmt.AuthStatusMFARequired,
				MFA: &mgmt.MFAChallenge{
					Token:       "tok-1",
					Prompt:      serverPrompt,
					PollAfterMS: 1,
					ExpiresAt:   time.Now().Add(time.Minute),
				},
			})
		},
		mgmt.PathPollMFA: func(w http.ResponseWriter, _ *http.Request) {
			if polls.Add(1) <= 2 {
				writeJSON(t, w, http.StatusOK, mgmt.AuthenticateResponse{
					Status: mgmt.AuthStatusMFARequired,
					MFA:    &mgmt.MFAChallenge{Token: "tok-1", PollAfterMS: 1, ExpiresAt: time.Now().Add(time.Minute)},
				})
				return
			}
			writeJSON(t, w, http.StatusOK, mgmt.AuthenticateResponse{
				Status:   mgmt.AuthStatusAuthenticated,
				Identity: aliceIdentity(),
			})
		},
	})

	logger, logs := testLogger()
	registry, err := NewFromConfig(
		config.UserAuth{Methods: config.DefaultUserAuthMethods(), MFA: config.MFA{
			MinPollInterval:  time.Millisecond,
			ProgressInterval: time.Millisecond,
			MaxWait:          10 * time.Second,
		}},
		Options{Client: client, Logger: logger},
	)
	if err != nil {
		t.Fatalf("NewFromConfig returned error: %v", err)
	}

	signer, _ := testKey(t)
	kbi := &kbiRecorder{}

	result := runHandshake(t, newServerAuth(t, registry), "alice#db01.corp.example.com", []ssh.AuthMethod{
		ssh.PublicKeys(signer),
		kbi.authMethod(testPassword),
	})
	if result.clientErr != nil {
		t.Fatalf("client handshake failed: %v", result.clientErr)
	}
	if result.serverErr != nil {
		t.Fatalf("server handshake failed: %v", result.serverErr)
	}

	// The authenticated identity must reach the connection the proxy will use.
	id, err := IdentityFromPermissions(result.serverConn.Permissions)
	if err != nil {
		t.Fatalf("IdentityFromPermissions returned error: %v", err)
	}
	if got, want := id.Subject, "alice@example.com"; got != want {
		t.Errorf("Subject = %q, want %q", got, want)
	}
	if got, want := id.Method, identity.MethodPasswordMFA; got != want {
		t.Errorf("Method = %q, want %q (the key was rejected)", got, want)
	}
	// The login is the SSH username with the target stripped (D1).
	if got, want := id.Login, "alice"; got != want {
		t.Errorf("Login = %q, want %q", got, want)
	}

	// The pre-auth banner is the explanation of the pause; it carries the
	// session id so a user who ends up filing a ticket already has the
	// reference. (The rejected key also produces a banner — the generic deny —
	// which is why this looks for the pre-auth one rather than checking all.)
	var sawPreAuthBanner bool
	for _, b := range result.banners {
		if strings.Contains(b, testMeta().SessionID) {
			sawPreAuthBanner = true
		}
	}
	if !sawPreAuthBanner {
		t.Errorf("banners = %q, want the pre-auth banner carrying the session id", result.banners)
	}

	prompts := kbi.snapshot()
	if len(prompts) < 2 {
		t.Fatalf("keyboard-interactive requests = %d, want the password prompt plus at least one MFA message", len(prompts))
	}
	if got := prompts[0].questions; len(got) != 1 || got[0] != PasswordPrompt {
		t.Errorf("first request questions = %v, want [%q]", got, PasswordPrompt)
	}

	// The server's MFA prompt must arrive in the instruction field, and the
	// wait must produce further messages rather than silence.
	var sawPrompt bool
	var waits int
	for _, p := range prompts[1:] {
		if len(p.questions) != 0 {
			t.Errorf("MFA request asked %v, want a zero-prompt info request", p.questions)
		}
		if strings.Contains(p.instruction, serverPrompt) {
			sawPrompt = true
		}
		waits++
	}
	if !sawPrompt {
		t.Errorf("the server's MFA prompt never reached the instruction field; requests = %+v", prompts)
	}
	if waits < 2 {
		t.Errorf("MFA info requests = %d, want the challenge plus at least one 'still waiting' ping", waits)
	}

	if strings.Contains(logs.String(), testPassword) {
		t.Errorf("password appeared in the logs:\n%s", logs.String())
	}
}

// TestHandshakeAcceptsCertificateWithoutPrompting is the certificate-first half:
// a key the server accepts finishes authentication with no password prompt at
// all.
func TestHandshakeAcceptsCertificateWithoutPrompting(t *testing.T) {
	_, client := newRecordingServer(t, map[string]http.HandlerFunc{
		mgmt.PathAuthenticateCert: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, mgmt.AuthenticateResponse{
				Status:   mgmt.AuthStatusAuthenticated,
				Identity: aliceIdentity(),
			})
		},
		mgmt.PathAuthenticatePassword: func(w http.ResponseWriter, _ *http.Request) {
			t.Error("password authentication was attempted after the key was accepted")
			writeDeny(t, w, "unexpected", "unexpected")
		},
	})

	registry, err := NewFromConfig(config.UserAuth{Methods: config.DefaultUserAuthMethods()}, Options{Client: client})
	if err != nil {
		t.Fatalf("NewFromConfig returned error: %v", err)
	}

	signer, _ := testKey(t)
	kbi := &kbiRecorder{}

	result := runHandshake(t, newServerAuth(t, registry), "alice#db01.corp.example.com", []ssh.AuthMethod{
		ssh.PublicKeys(signer),
		kbi.authMethod(testPassword),
	})
	if result.clientErr != nil {
		t.Fatalf("client handshake failed: %v", result.clientErr)
	}

	id, err := IdentityFromPermissions(result.serverConn.Permissions)
	if err != nil {
		t.Fatalf("IdentityFromPermissions returned error: %v", err)
	}
	if got, want := id.Method, identity.MethodCert; got != want {
		t.Errorf("Method = %q, want %q", got, want)
	}

	if prompts := kbi.snapshot(); len(prompts) != 0 {
		t.Errorf("keyboard-interactive requests = %+v, want none for an accepted key", prompts)
	}
}

// TestHandshakeDeniedTellsTheUser checks that a refused login is not a silent
// disconnect: the generic deny text reaches the client as a banner.
func TestHandshakeDeniedTellsTheUser(t *testing.T) {
	_, client := newRecordingServer(t, map[string]http.HandlerFunc{
		mgmt.PathAuthenticateCert: func(w http.ResponseWriter, _ *http.Request) {
			writeDeny(t, w, "unknown_key", "no")
		},
		mgmt.PathAuthenticatePassword: func(w http.ResponseWriter, _ *http.Request) {
			writeDeny(t, w, "bad_credentials", "no")
		},
	})

	registry, err := NewFromConfig(config.UserAuth{Methods: config.DefaultUserAuthMethods()}, Options{Client: client})
	if err != nil {
		t.Fatalf("NewFromConfig returned error: %v", err)
	}

	signer, _ := testKey(t)
	kbi := &kbiRecorder{}

	result := runHandshake(t, newServerAuth(t, registry), "alice#db01.corp.example.com", []ssh.AuthMethod{
		ssh.PublicKeys(signer),
		kbi.authMethod(testPassword),
	})
	if result.clientErr == nil {
		t.Fatal("client handshake succeeded, want it refused")
	}

	joined := strings.Join(result.banners, "\n")
	if !strings.Contains(joined, DenyMessage) {
		t.Errorf("banners = %q, want the deny message %q to reach the user", result.banners, DenyMessage)
	}
	if strings.Contains(joined, testMeta().Target) {
		t.Errorf("banners = %q, want no mention of the target", result.banners)
	}
}
