// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultAdminShell is the remote command the provisioning scripts are handed
// to. A provisioning account that is not root sets auth.target.ephemeral.shell
// to something like "sudo -n sh -c" instead: the whole script then runs inside
// one privileged shell, so a redirect into a root-owned directory works without
// the proxy having to reason about which individual command needs the
// privilege.
const DefaultAdminShell = "sh -c"

// DefaultAdminTimeout bounds one management login and the script it runs.
const DefaultAdminTimeout = 30 * time.Second

// AdminSession is one privileged login to a target: the management-certificate
// connection the ephemeral provisioner does its work over (D6, PLAN §5.1).
//
// It is an interface because it is the seam every ephemeral test needs. The
// alternative — tests that reach a real target — is exactly the thing that
// makes provisioning code untested in practice, and untested teardown is how
// accounts get left behind.
type AdminSession interface {
	// Run executes one shell script on the target and returns its stdout.
	// A non-zero exit is an error carrying the script's stderr.
	Run(ctx context.Context, script string) ([]byte, error)
	// HostKey is the key the target presented on this connection. Teardown
	// pins to it, so removing an account never depends on the policy service
	// still being reachable.
	HostKey() ssh.PublicKey
	// Close ends the privileged login.
	Close() error
}

// AdminDialer opens privileged logins to targets.
type AdminDialer interface {
	Dial(ctx context.Context, tgt Target) (AdminSession, error)
}

// RemoteCommandError is a provisioning script that ran and failed.
//
// It carries the target's stderr because that is the only thing that explains
// "useradd: cannot create directory" to whoever is on call, and provisioning
// scripts are the one place in this package where nothing secret can appear in
// a command or its output: the private half of the ephemeral key never leaves
// the proxy, and the public half is public.
type RemoteCommandError struct {
	// Stage names what the script was doing ("provision", "teardown", "sweep").
	Stage string
	// ExitStatus is the remote exit status, or -1 if the command never ran.
	ExitStatus int
	// Stderr is the target's stderr, truncated.
	Stderr string
	// Err is the underlying transport or exec error.
	Err error
}

func (e *RemoteCommandError) Error() string {
	msg := fmt.Sprintf("auth/target: %s script failed", e.Stage)
	if e.ExitStatus >= 0 {
		msg += fmt.Sprintf(" (exit %d)", e.ExitStatus)
	}
	if e.Stderr != "" {
		msg += ": " + e.Stderr
	}
	if e.Err != nil && e.Stderr == "" {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *RemoteCommandError) Unwrap() error { return e.Err }

// maxStderr bounds how much of a failing script's stderr is kept. A target that
// answers a provisioning command with a megabyte of output is a target having a
// bad day, not a reason to hold a megabyte per failed session.
const maxStderr = 2048

// SSHAdminOptions configures the production AdminDialer.
type SSHAdminOptions struct {
	// Signer is the management certificate's key, preloaded on targets (D6).
	// Required.
	Signer ssh.Signer
	// User is the privileged provisioning account. Required.
	User string
	// Shell is the remote command scripts are passed to. Empty means
	// DefaultAdminShell.
	Shell string
	// Timeout bounds the dial and each script. Zero means DefaultAdminTimeout.
	Timeout time.Duration
}

// sshAdminDialer opens the management login over SSH.
type sshAdminDialer struct {
	signer  ssh.Signer
	user    string
	shell   string
	timeout time.Duration
}

// NewSSHAdminDialer returns the AdminDialer used in production: a management
// certificate login as the provisioning account.
func NewSSHAdminDialer(opts SSHAdminOptions) (AdminDialer, error) {
	switch {
	case opts.Signer == nil:
		return nil, errors.New("auth/target: the management connection requires a key")
	case opts.User == "":
		return nil, errors.New("auth/target: the management connection requires a provisioning account")
	}
	d := &sshAdminDialer{
		signer:  opts.Signer,
		user:    opts.User,
		shell:   opts.Shell,
		timeout: opts.Timeout,
	}
	if d.shell == "" {
		d.shell = DefaultAdminShell
	}
	if d.timeout <= 0 {
		d.timeout = DefaultAdminTimeout
	}
	return d, nil
}

// Dial opens the privileged login.
//
// The host-key policy is the caller's (D7): a session hands its own callback
// down on the Target, and a teardown or a reaper sweep pins to the key the
// provisioning login already saw. There is no third case, and no default that
// trusts anything — a nil callback is an error rather than a shrug, because the
// management login is the most privileged connection this proxy makes.
func (d *sshAdminDialer) Dial(ctx context.Context, tgt Target) (AdminSession, error) {
	if tgt.HostKeyCallback == nil {
		return nil, errors.New("auth/target: the management connection has no host key policy")
	}

	var seen ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: d.user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(d.signer)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if err := tgt.HostKeyCallback(hostname, remote, key); err != nil {
				return err
			}
			seen = key
			return nil
		},
		Timeout: d.timeout,
	}

	addr := tgt.Addr()
	dialer := net.Dialer{Timeout: d.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("auth/target: dial management connection to %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(d.timeout))
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("auth/target: management login to %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Time{})

	return &sshAdminSession{
		client:  ssh.NewClient(sshConn, chans, reqs),
		hostKey: seen,
		shell:   d.shell,
		timeout: d.timeout,
	}, nil
}

// sshAdminSession runs scripts over one management login.
type sshAdminSession struct {
	client  *ssh.Client
	hostKey ssh.PublicKey
	shell   string
	timeout time.Duration
}

func (s *sshAdminSession) HostKey() ssh.PublicKey { return s.hostKey }

func (s *sshAdminSession) Close() error { return s.client.Close() }

// Run executes one script and returns its stdout.
func (s *sshAdminSession) Run(ctx context.Context, script string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	sess, err := s.client.NewSession()
	if err != nil {
		return nil, &RemoteCommandError{ExitStatus: -1, Err: err}
	}
	defer func() { _ = sess.Close() }()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- sess.Run(s.shell + " " + shellQuote(script)) }()

	select {
	case err := <-done:
		if err != nil {
			return stdout.Bytes(), &RemoteCommandError{
				ExitStatus: exitStatus(err),
				Stderr:     truncate(stderr.String(), maxStderr),
				Err:        err,
			}
		}
		return stdout.Bytes(), nil
	case <-ctx.Done():
		// Abandoning the session rather than waiting is deliberate: a wedged
		// provisioning script must not hold a user at an SSH prompt, and the
		// account it may have half-created is the orphan reaper's problem,
		// which is why the reaper exists.
		_ = sess.Signal(ssh.SIGKILL)
		return nil, &RemoteCommandError{ExitStatus: -1, Err: ctx.Err()}
	}
}

// exitStatus recovers the remote exit status from x/crypto's error, or -1 when
// the command did not run at all.
func exitStatus(err error) int {
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus()
	}
	return -1
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// shellQuote wraps a script in single quotes for the remote shell.
//
// Every value interpolated into a script is validated first — principals
// against validatePrincipal, paths against validatePath, key material against
// validateScriptValue — so nothing reaching here should need escaping at all.
// It escapes anyway: "validated upstream" is a property of today's callers, and
// a provisioning script runs as root on someone's fleet.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
