// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package sshtest

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

// ExecFunc runs one exec request and returns what the "program" produced.
type ExecFunc func(command string) (stdout, stderr []byte, status uint32)

// ShellFunc runs one interactive shell against the channel's byte stream and
// returns the exit status.
type ShellFunc func(rw io.ReadWriter) uint32

// Options configures a Target.
type Options struct {
	// HostKey is the target's host key. Generated when nil.
	HostKey ssh.Signer
	// Exec handles exec requests. Nil echoes the command back with status 0.
	Exec ExecFunc
	// Shell handles shell requests. Nil echoes input until EOF with status 0.
	Shell ShellFunc
	// AllowedChannels are the channel types the target accepts. Nil means
	// "session" and "direct-tcpip".
	AllowedChannels []string
}

// Target is an in-process SSH server standing in for a target host. It accepts
// any public key: authentication to the target is the bastion's problem, and a
// test that had to manage the target's authorized_keys would be testing the
// wrong thing.
type Target struct {
	listener net.Listener
	config   *ssh.ServerConfig
	hostKey  ssh.Signer
	exec     ExecFunc
	shell    ShellFunc
	allowed  map[string]bool

	wg     sync.WaitGroup
	closed chan struct{}

	mu       sync.Mutex
	logins   []string
	commands []string
	ptys     int
	envs     []string
}

// StartTarget starts a target on a loopback port.
func StartTarget(opts Options) (*Target, error) {
	hostKey := opts.HostKey
	if hostKey == nil {
		var err error
		if hostKey, err = GenerateSigner(); err != nil {
			return nil, err
		}
	}

	t := &Target{
		hostKey: hostKey,
		exec:    opts.Exec,
		shell:   opts.Shell,
		allowed: make(map[string]bool),
		closed:  make(chan struct{}),
	}
	if t.exec == nil {
		t.exec = echoExec
	}
	if t.shell == nil {
		t.shell = echoShell
	}
	allowed := opts.AllowedChannels
	if allowed == nil {
		allowed = []string{"session", "direct-tcpip"}
	}
	for _, name := range allowed {
		t.allowed[name] = true
	}

	t.config = &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
			t.record(func() { t.logins = append(t.logins, conn.User()) })
			return &ssh.Permissions{}, nil
		},
	}
	t.config.AddHostKey(hostKey)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("sshtest: listen: %w", err)
	}
	t.listener = l

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.serve()
	}()
	return t, nil
}

// Addr is the address the target listens on.
func (t *Target) Addr() net.Addr { return t.listener.Addr() }

// Host is the target's host, as a route would name it.
func (t *Target) Host() string {
	host, _, _ := net.SplitHostPort(t.listener.Addr().String())
	return host
}

// Port is the target's SSH port.
func (t *Target) Port() int {
	_, port, _ := net.SplitHostPort(t.listener.Addr().String())
	n, _ := strconv.Atoi(port)
	return n
}

// HostKey is the public host key the target presents.
func (t *Target) HostKey() ssh.PublicKey { return t.hostKey.PublicKey() }

// Logins are the usernames the bastion logged in as, in order.
func (t *Target) Logins() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.logins...)
}

// Commands are the exec requests the target received, in order.
func (t *Target) Commands() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.commands...)
}

// PTYs is how many pty-req requests reached the target — the proof that a
// request the proxy holds while the leg comes up is really replayed.
func (t *Target) PTYs() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ptys
}

// Envs are the env requests the target received, as "NAME=value".
func (t *Target) Envs() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.envs...)
}

// Close stops the target and waits for its connections to end.
func (t *Target) Close() error {
	select {
	case <-t.closed:
		return nil
	default:
	}
	close(t.closed)
	err := t.listener.Close()
	t.wg.Wait()
	return err
}

func (t *Target) serve() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			return
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			t.handleConn(conn)
		}()
	}
}

func (t *Target) handleConn(conn net.Conn) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, t.config)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = sshConn.Close() }()

	go ssh.DiscardRequests(reqs)

	var wg sync.WaitGroup
	for newChannel := range chans {
		if !t.allowed[newChannel.ChannelType()] {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		wg.Add(1)
		go func(ch ssh.Channel, in <-chan *ssh.Request, kind string) {
			defer wg.Done()
			if kind == "session" {
				t.handleSession(ch, in)
				return
			}
			t.handleForward(ch, in)
		}(channel, requests, newChannel.ChannelType())
	}
	wg.Wait()
}

// handleSession implements just enough of an sshd session to prove a proxy
// works: pty and env are recorded, exec and shell run, and every channel ends
// with an exit status.
func (t *Target) handleSession(ch ssh.Channel, in <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()

	for req := range in {
		switch req.Type {
		case "pty-req":
			t.record(func() { t.ptys++ })
			reply(req, true)
		case "env":
			var env struct{ Name, Value string }
			if err := ssh.Unmarshal(req.Payload, &env); err == nil {
				t.record(func() { t.envs = append(t.envs, env.Name+"="+env.Value) })
			}
			reply(req, true)
		case "window-change":
			reply(req, true)
		case "exec":
			var payload struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				reply(req, false)
				return
			}
			t.record(func() { t.commands = append(t.commands, payload.Command) })
			reply(req, true)
			stdout, stderr, status := t.exec(payload.Command)
			_, _ = ch.Write(stdout)
			_, _ = ch.Stderr().Write(stderr)
			sendExit(ch, status)
			return
		case "shell":
			reply(req, true)
			status := t.shell(ch)
			sendExit(ch, status)
			return
		default:
			reply(req, false)
		}
	}
}

// handleForward echoes on a non-session channel, which is all a passthrough
// test needs from one.
func (t *Target) handleForward(ch ssh.Channel, in <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	go ssh.DiscardRequests(in)
	_, _ = io.Copy(ch, ch)
}

func (t *Target) record(f func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f()
}

// echoExec is the default program: it prints the command it was given, so a
// test can tell an exec that arrived intact from one that did not.
func echoExec(command string) ([]byte, []byte, uint32) {
	return []byte("ran: " + command + "\n"), nil, 0
}

// echoShell echoes what it is sent until the stream ends.
func echoShell(rw io.ReadWriter) uint32 {
	buf := make([]byte, 1024)
	for {
		n, err := rw.Read(buf)
		if n > 0 {
			if _, werr := rw.Write(buf[:n]); werr != nil {
				return 1
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0
			}
			return 1
		}
	}
}

func reply(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

func sendExit(ch ssh.Channel, status uint32) {
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
}
