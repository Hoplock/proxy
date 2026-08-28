// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package device

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultShellTimeout bounds one privileged CLI session on a device.
//
// It is generous compared with the POSIX path's script timeout because a device
// CLI is a conversation rather than a command: a FortiGate that is busy
// applying a configuration change answers late, and a timeout tuned for a shell
// turns that into a half-created administrator.
const DefaultShellTimeout = 45 * time.Second

// Shell is one privileged interactive CLI session on a device.
//
// It is a byte pipe and nothing more. Everything above it — what a prompt looks
// like, which output is an error, how paging is answered — is the DRIVER's,
// because those are the parts that differ per platform and the parts a
// declarative driver document will eventually describe. Keeping them out of
// here is what stops this file from quietly becoming a second driver seam.
type Shell interface {
	io.ReadWriteCloser
	// HostKey is the key the device presented on this connection, so teardown
	// and sweeps can pin to it.
	HostKey() ssh.PublicKey
}

// ShellDialer opens privileged CLI sessions to devices.
//
// It is an interface for the same reason target.AdminDialer is: it is the seam
// every driver test needs, and a provisioner whose teardown is only testable
// against real hardware is a provisioner whose teardown is not tested.
type ShellDialer interface {
	Shell(ctx context.Context, ep Endpoint) (Shell, error)
}

// SSHShellOptions configures the production ShellDialer.
type SSHShellOptions struct {
	// User is the privileged administrator the proxy logs in as. Required.
	User string
	// Password authenticates that administrator. It is credential material: it
	// is never logged and never appears in an error.
	Password string
	// Signer authenticates that administrator by key, where the device holds
	// one. Either this or Password is required; both may be set, and the key
	// is offered first.
	Signer ssh.Signer
	// Timeout bounds the dial and the login. Zero means DefaultShellTimeout.
	Timeout time.Duration
	// HostKeyAlgorithms narrows what the device may present. Empty means the
	// library's defaults; a fleet of appliances too old for them is what
	// contract v3's algorithm profile is for.
	HostKeyAlgorithms []string
	// KeyExchanges and Ciphers likewise, for the same reason.
	KeyExchanges []string
	Ciphers      []string
}

type sshShellDialer struct {
	opts SSHShellOptions
}

// NewSSHShellDialer returns the ShellDialer used in production.
func NewSSHShellDialer(opts SSHShellOptions) (ShellDialer, error) {
	if opts.User == "" {
		return nil, errors.New("auth/target/device: the device management login requires an administrator name")
	}
	if opts.Password == "" && opts.Signer == nil {
		return nil, errors.New("auth/target/device: the device management login requires a password or a key")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultShellTimeout
	}
	return &sshShellDialer{opts: opts}, nil
}

// Shell opens the privileged CLI session.
func (d *sshShellDialer) Shell(ctx context.Context, ep Endpoint) (Shell, error) {
	if ep.HostKeyCallback == nil {
		// The same refusal target.sshAdminDialer makes, for the same reason:
		// this is the most privileged connection the proxy opens, and a
		// default that trusts anything would make the device's identity the
		// one thing in the chain nobody checked.
		return nil, errors.New("auth/target/device: the device management connection has no host key policy")
	}

	var auth []ssh.AuthMethod
	if d.opts.Signer != nil {
		auth = append(auth, ssh.PublicKeys(d.opts.Signer))
	}
	if d.opts.Password != "" {
		auth = append(auth, ssh.Password(d.opts.Password))
	}

	var seen ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: d.opts.User,
		Auth: auth,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if err := ep.HostKeyCallback(hostname, remote, key); err != nil {
				return err
			}
			seen = key
			return nil
		},
		HostKeyAlgorithms: d.opts.HostKeyAlgorithms,
		Timeout:           d.opts.Timeout,
	}
	cfg.KeyExchanges = d.opts.KeyExchanges
	cfg.Ciphers = d.opts.Ciphers

	addr := net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))
	dialer := net.Dialer{Timeout: d.opts.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("auth/target/device: dial %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(d.opts.Timeout))
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		// The error is not wrapped with the login name or anything from the
		// credential: a failed device login is one of the few places where a
		// helpful message is a disclosure.
		return nil, fmt.Errorf("auth/target/device: management login to %s failed", addr)
	}
	_ = conn.SetDeadline(time.Time{})

	client := ssh.NewClient(sshConn, chans, reqs)
	sess, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("auth/target/device: open a CLI session on %s: %w", addr, err)
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, fmt.Errorf("auth/target/device: attach to the CLI on %s: %w", addr, err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, fmt.Errorf("auth/target/device: attach to the CLI on %s: %w", addr, err)
	}

	// A device CLI is an interactive program, not a command pipe: it prints a
	// prompt, waits, and pages long output. Asking for a shell rather than an
	// exec is therefore not a stylistic choice — most appliance SSH servers
	// answer an exec request with nothing at all.
	if err := sess.Shell(); err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, fmt.Errorf("auth/target/device: start the CLI on %s: %w", addr, err)
	}

	return &sshShell{
		client:  client,
		session: sess,
		stdin:   stdin,
		stdout:  stdout,
		hostKey: seen,
	}, nil
}

type sshShell struct {
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	hostKey ssh.PublicKey
}

func (s *sshShell) Read(p []byte) (int, error)  { return s.stdout.Read(p) }
func (s *sshShell) Write(p []byte) (int, error) { return s.stdin.Write(p) }
func (s *sshShell) HostKey() ssh.PublicKey      { return s.hostKey }

func (s *sshShell) Close() error {
	_ = s.stdin.Close()
	_ = s.session.Close()
	return s.client.Close()
}
