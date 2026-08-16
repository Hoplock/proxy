// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mauroasilva/securecommandproxy/internal/auth/target"
	"github.com/mauroasilva/securecommandproxy/internal/auth/user"
	"github.com/mauroasilva/securecommandproxy/internal/mgmt"
	"github.com/mauroasilva/securecommandproxy/internal/routing"
)

// Engine defaults. All are bounds on waiting, not policy: nothing here decides
// anything, it only stops a stalled dependency from becoming an unbounded wait
// for someone at an SSH prompt.
const (
	// DefaultDialTimeout bounds the target leg: TCP connect plus SSH handshake,
	// including the host-key report round trip inside it.
	DefaultDialTimeout = 15 * time.Second
	// DefaultAuthTimeout bounds an unauthenticated connection. Authentication
	// can legitimately take a while (an MFA approval is a human tapping a
	// phone), so this is generous; it exists to stop an idle unauthenticated
	// socket from living forever.
	DefaultAuthTimeout = 3 * time.Minute
	// defaultServerVersion identifies the bastion to clients. It must start
	// with "SSH-2.0-" per RFC 4253.
	defaultServerVersion = "SSH-2.0-SecureCommandProxy"
)

// ShutdownReason is shown to every live session when the bastion stops. A
// bastion going away owes its users the same explanation a revocation does
// (PLAN §4.3): silence would be indistinguishable from a crash.
const ShutdownReason = "the bastion is shutting down"

// Options configures a Server.
type Options struct {
	// HostKey is the bastion's own SSH host key, presented to clients.
	// Required.
	HostKey ssh.Signer
	// Authenticator authenticates users; normally a *user.Registry. Required.
	Authenticator user.UserAuthenticator
	// Resolver turns an identity plus a target into the connection's policy.
	// Required.
	Resolver *routing.Resolver
	// TargetAuth provisions the credentials for the target leg. Required.
	TargetAuth target.TargetAuthenticator
	// Client is the management API client, used here for the host-key report
	// (D7). Required.
	Client mgmt.Client
	// BastionID identifies this bastion on every management call. Required.
	BastionID string
	// TargetDelimiter splits the SSH username into login and target (D1).
	// Required, and validated by config.
	TargetDelimiter string
	// DialTimeout bounds the target leg. Zero means DefaultDialTimeout.
	DialTimeout time.Duration
	// AuthTimeout bounds an unauthenticated connection. Zero means
	// DefaultAuthTimeout; negative disables the bound.
	AuthTimeout time.Duration
	// ServerVersion overrides the SSH identification string.
	ServerVersion string
	// Logger receives session lifecycle events; nil discards them. It is never
	// given a credential.
	Logger *log.Logger
	// Now overrides the clock, for tests. Nil means time.Now.
	Now func() time.Time
	// NewSessionID overrides session id generation, for tests.
	NewSessionID func() string
}

// Server is the core SSH proxy engine (PLAN §3).
//
// It terminates the client's SSH connection, authorizes it against the
// management server, opens a fresh SSH connection to the target, and proxies
// every channel between the two. Both legs are decrypted inside the process,
// which is what later phases inspect (0008) and filter (0009); this phase
// establishes the transport and the session lifecycle underneath them.
//
// It also implements mgmt.SessionRegistry, so the management server's
// revocation stream can end a session that is already in flight (PLAN §6.4).
type Server struct {
	hostKey       ssh.Signer
	auth          user.UserAuthenticator
	resolver      *routing.Resolver
	targetAuth    target.TargetAuthenticator
	client        mgmt.Client
	bastionID     string
	delimiter     string
	dialTimeout   time.Duration
	authTimeout   time.Duration
	serverVersion string
	logger        *log.Logger
	now           func() time.Time
	newSessionID  func() string

	mu       sync.Mutex
	sessions map[string]*session

	conns sync.WaitGroup
}

var _ mgmt.SessionRegistry = (*Server)(nil)

// New validates opts and returns a Server.
func New(opts Options) (*Server, error) {
	switch {
	case opts.HostKey == nil:
		return nil, errors.New("proxy: a host key is required")
	case opts.Authenticator == nil:
		return nil, errors.New("proxy: a user authenticator is required")
	case opts.Resolver == nil:
		return nil, errors.New("proxy: a route resolver is required")
	case opts.TargetAuth == nil:
		return nil, errors.New("proxy: a target authenticator is required")
	case opts.Client == nil:
		return nil, errors.New("proxy: a management client is required")
	case opts.BastionID == "":
		return nil, errors.New("proxy: a bastion id is required")
	case opts.TargetDelimiter == "":
		return nil, errors.New("proxy: a target delimiter is required")
	}

	s := &Server{
		hostKey:       opts.HostKey,
		auth:          opts.Authenticator,
		resolver:      opts.Resolver,
		targetAuth:    opts.TargetAuth,
		client:        opts.Client,
		bastionID:     opts.BastionID,
		delimiter:     opts.TargetDelimiter,
		dialTimeout:   opts.DialTimeout,
		authTimeout:   opts.AuthTimeout,
		serverVersion: opts.ServerVersion,
		logger:        opts.Logger,
		now:           opts.Now,
		newSessionID:  opts.NewSessionID,
		sessions:      make(map[string]*session),
	}
	if s.dialTimeout <= 0 {
		s.dialTimeout = DefaultDialTimeout
	}
	if s.authTimeout == 0 {
		s.authTimeout = DefaultAuthTimeout
	}
	if s.serverVersion == "" {
		s.serverVersion = defaultServerVersion
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.newSessionID == nil {
		s.newSessionID = newSessionID
	}
	return s, nil
}

// Serve accepts connections until ctx ends or the listener fails.
//
// When ctx ends it stops accepting, tells every live session why it is going
// away, and waits for them to finish, so a shutdown is a close the user can
// read rather than a dropped socket.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			// Detached from ctx: the kill messages are written while the
			// context that just ended is the reason for writing them.
			_ = s.KillAll(context.WithoutCancel(ctx), ShutdownReason)
		case <-done:
		}
		_ = l.Close()
	}()

	var serveErr error
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() == nil {
				serveErr = fmt.Errorf("proxy: accept: %w", err)
			}
			break
		}
		s.conns.Add(1)
		go func() {
			defer s.conns.Done()
			s.handleConn(ctx, conn)
		}()
	}

	s.conns.Wait()
	return serveErr
}

// handleConn runs one client connection from handshake to teardown.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	sessionID := s.newSessionID()
	remote := conn.RemoteAddr().String()

	// One connection must never be able to stop the bastion serving every other
	// one. A panic before the session exists has nowhere to be reported, so it
	// is logged and the connection dropped.
	defer func() {
		if r := recover(); r != nil {
			s.logf("proxy: session=%s client=%s panic: %v\n%s", sessionID, remote, r, debug.Stack())
			_ = conn.Close()
		}
	}()

	// An unauthenticated connection gets a deadline; it is cleared as soon as
	// the handshake succeeds, because a proxied session is legitimately idle
	// for hours.
	if s.authTimeout > 0 {
		_ = conn.SetDeadline(s.now().Add(s.authTimeout))
	}

	cfg, err := s.serverConfig(ctx, sessionID)
	if err != nil {
		s.logf("proxy: session=%s client=%s server config: %v", sessionID, remote, err)
		_ = conn.Close()
		return
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		// Authentication has already told the user why, through the banner the
		// auth plane attaches to its failures (PLAN §4.3). This is the log half.
		s.logf("proxy: session=%s client=%s handshake failed: %v", sessionID, remote, err)
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})

	sess := s.newSession(ctx, sessionID, sshConn, chans, reqs)
	s.add(sess)
	defer s.remove(sess)
	sess.run()
}

// serverConfig builds the client-facing SSH configuration for one connection.
//
// It is per-connection rather than shared because the session id has to reach
// the authentication plane: it is on every management call and is the support
// reference the user is given when something fails (PLAN §4.3).
func (s *Server) serverConfig(ctx context.Context, sessionID string) (*ssh.ServerConfig, error) {
	cfg := &ssh.ServerConfig{ServerVersion: s.serverVersion}
	cfg.AddHostKey(s.hostKey)

	auth, err := user.NewServerAuth(user.ServerAuthOptions{
		Authenticator: s.auth,
		BaseContext:   ctx,
		ConnMeta: func(conn ssh.ConnMetadata) user.ConnMeta {
			base := user.ConnMeta{SessionID: sessionID, BastionID: s.bastionID}
			// The target must be split off the username before the login is
			// presented for authentication (D1). A username that does not parse
			// is passed through whole: refusing it here would deny the
			// connection locally, and the bastion does not decide who exists —
			// the malformed name is reported to the user by the engine, after
			// the management server has had its say.
			login, tgt, err := routing.ParseUsername(conn.User(), s.delimiter)
			if err == nil {
				base.Login, base.Target = login, tgt
			} else {
				base.Login = conn.User()
			}
			return user.ConnMetaFromSSH(base, conn)
		},
	})
	if err != nil {
		return nil, err
	}
	auth.Apply(cfg)
	return cfg, nil
}

func (s *Server) add(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.id] = sess
}

func (s *Server) remove(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sess.id)
}

// snapshot copies the live sessions, so kills run without the lock held: a
// kill writes to a channel and closes a connection, and holding the registry
// lock across that would let one slow client stall every other kill.
func (s *Server) snapshot() []*session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, sess)
	}
	return out
}

func (s *Server) logf(format string, args ...any) {
	if s.logger == nil {
		return
	}
	s.logger.Printf(format, args...)
}

// newSessionID returns an unguessable session id. It is quoted to users as a
// support reference and correlates every log record and management call for the
// connection, so it must be unique and must not be derived from anything the
// client controls.
func newSessionID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail on any supported platform; if it ever does,
		// a session with a colliding id is worse than no session at all.
		panic("proxy: cannot generate a session id: " + err.Error())
	}
	return "sess-" + hex.EncodeToString(b[:])
}
