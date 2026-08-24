// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package channel

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
)

// testPolicy states a connection's policy as a literal. It is the same shape
// routing.Route exposes — the pipeline takes the interface precisely so a test
// does not have to build an authorize response to state one axis.
type testPolicy struct {
	channels []string
	requests *control.RequestPolicy
	forwards *control.ForwardPolicy
	globals  *control.GlobalRequestPolicy
}

func (p testPolicy) ChannelPermitted(channelType string) bool {
	for _, permitted := range p.channels {
		if permitted == channelType {
			return true
		}
	}
	return false
}

func (p testPolicy) RequestPermitted(name string) bool { return p.requests.RequestPermitted(name) }

func (p testPolicy) SubsystemPermitted(name string) bool {
	return p.requests.SubsystemPermitted(name)
}

func (p testPolicy) GlobalRequestPermitted(name string) bool { return p.globals.Permitted(name) }

func (p testPolicy) ForwardDestinations(channelType string) ([]control.ForwardDestination, bool) {
	return p.forwards.Destinations(channelType)
}

// newPipeline builds a pipeline over a policy, with an optional registry.
func newPipeline(t *testing.T, policy Policy, reg *Registry) *Pipeline {
	t.Helper()
	p, err := New(Options{Policy: policy, Inspectors: reg, SessionID: "session-1", Logf: t.Logf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestNewRequiresAPolicy(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("New with no policy returned no error; a pipeline with no policy could only fail open")
	}
}

// TestChannelTypeAxis is axis 1, including the two readings that must not blur:
// an empty allow-list denies everything, and the same list applies to a channel
// the target opens back.
func TestChannelTypeAxis(t *testing.T) {
	for _, tc := range []struct {
		name      string
		permitted []string
		open      string
		dir       Direction
		wantDeny  bool
	}{
		{"permitted from the client", []string{"session"}, "session", FromClient, false},
		{"denied from the client", []string{"session"}, "x11", FromClient, true},
		{"permitted from the target", []string{"x11"}, "x11", FromTarget, false},
		{"denied from the target", []string{"session"}, "x11", FromTarget, true},
		{"an empty allow-list denies", []string{}, "session", FromClient, true},
		{"a nil allow-list denies", nil, "session", FromClient, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPipeline(t, testPolicy{channels: tc.permitted}, nil)
			insp, decision := p.Open(context.Background(), OpenEvent{ChannelType: tc.open, Direction: tc.dir})
			if got := decision.Denied(); got != tc.wantDeny {
				t.Fatalf("denied = %t, want %t", got, tc.wantDeny)
			}
			if tc.wantDeny {
				if insp != nil {
					t.Error("a denied open still returned an inspection")
				}
				if !strings.Contains(decision.Reason, tc.open) {
					t.Errorf("reason %q does not name the channel type", decision.Reason)
				}
				return
			}
			if insp == nil {
				t.Fatal("a permitted open returned no inspection")
			}
			if got := insp.Opener(); got != tc.dir {
				t.Errorf("Opener() = %v, want %v", got, tc.dir)
			}
		})
	}
}

// TestForwardDestinationAxis is axis 3a: the destination inside the payload,
// which is the whole meaning of a forward.
func TestForwardDestinationAxis(t *testing.T) {
	dests := []control.ForwardDestination{{Host: "db.internal", Port: 5432}}
	p := newPipeline(t, testPolicy{
		channels: []string{control.ChannelDirectTCPIP, control.ChannelForwardedTCPIP},
		forwards: &control.ForwardPolicy{DirectTCPIP: dests},
	}, nil)

	for _, tc := range []struct {
		name        string
		channelType string
		host        string
		port        int
		wantDeny    bool
	}{
		{"the permitted destination", control.ChannelDirectTCPIP, "db.internal", 5432, false},
		{"another host", control.ChannelDirectTCPIP, "web.internal", 5432, true},
		{"another port on the same host", control.ChannelDirectTCPIP, "db.internal", 22, true},
		// The other direction has its own list, and this one is empty: a route
		// that may tunnel out to the database does not thereby accept channels
		// pushed the other way.
		{"the same destination in the other direction", control.ChannelForwardedTCPIP, "db.internal", 5432, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, decision := p.Open(context.Background(), OpenEvent{
				ChannelType: tc.channelType,
				Direction:   FromClient,
				Payload:     marshalForward(tc.host, tc.port),
			})
			if got := decision.Denied(); got != tc.wantDeny {
				t.Fatalf("denied = %t, want %t (reason %q)", got, tc.wantDeny, decision.Reason)
			}
		})
	}
}

// TestForwardDestinationsUnpoliced is the contract's absent value: a nil
// forward policy is a v1 server, and a v1 server meant "the channel type
// decides".
func TestForwardDestinationsUnpoliced(t *testing.T) {
	p := newPipeline(t, testPolicy{channels: []string{control.ChannelDirectTCPIP}}, nil)
	insp, decision := p.Open(context.Background(), OpenEvent{
		ChannelType: control.ChannelDirectTCPIP,
		Direction:   FromClient,
		Payload:     marshalForward("anywhere.example.com", 9999),
	})
	if decision.Denied() {
		t.Fatalf("an unpoliced destination was denied: %q", decision.Reason)
	}
	forward := insp.Info().Forward
	if forward == nil {
		t.Fatal("the parsed destination was not attached to the channel")
	}
	if got, want := forward.String(), "anywhere.example.com:9999"; got != want {
		t.Errorf("parsed destination = %q, want %q", got, want)
	}
}

// TestMalformedForwardPayloadIsDeniedWithoutPanicking covers the payload the
// pipeline is handed by whoever opened the channel. It is attacker-controlled,
// so the only two acceptable outcomes are "parsed" and "denied".
func TestMalformedForwardPayloadIsDeniedWithoutPanicking(t *testing.T) {
	p := newPipeline(t, testPolicy{
		channels: []string{control.ChannelDirectTCPIP},
		forwards: &control.ForwardPolicy{DirectTCPIP: []control.ForwardDestination{{Host: "*"}}},
	}, nil)

	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"a truncated length prefix", []byte{0x00, 0x00, 0x01}},
		{"a host length beyond the payload", []byte{0x00, 0x00, 0xff, 0xff, 'd', 'b'}},
		{"a missing origin", []byte{0x00, 0x00, 0x00, 0x02, 'd', 'b', 0x00, 0x00, 0x15, 0x38}},
		{"trailing junk", append(marshalForward("db.internal", 5432), 'x')},
		{"an empty host", marshalForward("", 5432)},
		{"a port beyond 65535", ssh.Marshal(struct {
			Host       string
			Port       uint32
			OriginHost string
			OriginPort uint32
		}{"db.internal", 70000, "127.0.0.1", 1})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parsing panicked: %v", r)
				}
			}()
			_, decision := p.Open(context.Background(), OpenEvent{
				ChannelType: control.ChannelDirectTCPIP,
				Direction:   FromClient,
				Payload:     tc.payload,
			})
			if !decision.Denied() {
				t.Fatal("a payload the proxy could not read was permitted")
			}
		})
	}
}

// TestRequestAxis is axis 2, enforced at the request because that is where SSH
// decides what a session channel is.
func TestRequestAxis(t *testing.T) {
	p := newPipeline(t, testPolicy{
		channels: []string{"session"},
		requests: &control.RequestPolicy{
			Types:      []string{control.RequestExec},
			Subsystems: []string{"sftp"},
		},
	}, nil)
	insp, decision := p.Open(context.Background(), OpenEvent{ChannelType: "session", Direction: FromClient})
	if decision.Denied() {
		t.Fatalf("the session channel was denied: %q", decision.Reason)
	}

	for _, tc := range []struct {
		name     string
		reqType  string
		payload  []byte
		wantDeny bool
	}{
		{"a permitted exec", control.RequestExec, ssh.Marshal(struct{ Command string }{"uptime"}), false},
		{"a denied pty", control.RequestPTY, nil, true},
		{"a denied shell", control.RequestShell, nil, true},
		{"a permitted subsystem", control.RequestSubsystem, ssh.Marshal(struct{ Name string }{"sftp"}), false},
		{"a denied subsystem", control.RequestSubsystem, ssh.Marshal(struct{ Name string }{"netconf"}), true},
		{"a malformed subsystem", control.RequestSubsystem, []byte{0xff}, true},
		{"a malformed exec", control.RequestExec, []byte{0xff}, true},
		// Ancillary requests decide nothing and are always relayed.
		{"a terminal resize", "window-change", nil, false},
		{"an exit status", "exit-status", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := insp.Request(context.Background(), RequestEvent{Type: tc.reqType, Payload: tc.payload})
			if got := d.Denied(); got != tc.wantDeny {
				t.Fatalf("denied = %t, want %t (reason %q)", got, tc.wantDeny, d.Reason)
			}
			if tc.wantDeny && d.Reason == "" {
				t.Error("a denial with no reason is a silent failure (PLAN §4.3)")
			}
		})
	}
}

// TestRequestAxisAbsentMeansUnpoliced is the contract's absent value for
// axis 2: a v1 server never heard of the field, and must not thereby deny every
// shell in the estate.
func TestRequestAxisAbsentMeansUnpoliced(t *testing.T) {
	p := newPipeline(t, testPolicy{channels: []string{"session"}}, nil)
	insp, _ := p.Open(context.Background(), OpenEvent{ChannelType: "session", Direction: FromClient})
	for _, name := range []string{control.RequestPTY, control.RequestShell, control.RequestExec} {
		payload := []byte(nil)
		if name == control.RequestExec {
			payload = ssh.Marshal(struct{ Command string }{"uptime"})
		}
		if d := insp.Request(context.Background(), RequestEvent{Type: name, Payload: payload}); d.Denied() {
			t.Errorf("%s was denied by an absent request policy", name)
		}
	}
	if d := insp.Request(context.Background(), RequestEvent{
		Type:    control.RequestSubsystem,
		Payload: ssh.Marshal(struct{ Name string }{"sftp"}),
	}); d.Denied() {
		t.Error("sftp was denied by an absent request policy")
	}
}

// TestGlobalRequestAxis is axis 3b. Remote forwarding never appears as a
// channel open, so only this axis can refuse it.
func TestGlobalRequestAxis(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policy   *control.GlobalRequestPolicy
		request  string
		wantDeny bool
	}{
		{"an absent policy relays", nil, control.GlobalRequestTCPIPForward, false},
		{"an empty policy denies", &control.GlobalRequestPolicy{}, control.GlobalRequestTCPIPForward, true},
		{"a named request is relayed", &control.GlobalRequestPolicy{
			Types: []string{control.GlobalRequestTCPIPForward},
		}, control.GlobalRequestTCPIPForward, false},
		{"an unnamed request is denied", &control.GlobalRequestPolicy{
			Types: []string{control.GlobalRequestTCPIPForward},
		}, control.GlobalRequestStreamLocalForward, true},
		{"transport hygiene is never policy", &control.GlobalRequestPolicy{}, "keepalive@openssh.com", false},
		{"nor is no-more-sessions", &control.GlobalRequestPolicy{}, "no-more-sessions@openssh.com", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPipeline(t, testPolicy{globals: tc.policy}, nil)
			if got := p.GlobalRequest(context.Background(), tc.request).Denied(); got != tc.wantDeny {
				t.Errorf("denied = %t, want %t", got, tc.wantDeny)
			}
		})
	}
}

func TestRequestStartsExecution(t *testing.T) {
	for name, want := range map[string]bool{
		control.RequestShell:     true,
		control.RequestExec:      true,
		control.RequestSubsystem: true,
		control.RequestPTY:       false,
		control.RequestEnv:       false,
		"window-change":          false,
	} {
		if got := RequestStartsExecution(name); got != want {
			t.Errorf("RequestStartsExecution(%q) = %t, want %t", name, got, want)
		}
	}
}

func marshalForward(host string, port int) []byte {
	return ssh.Marshal(struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}{host, uint32(port), "127.0.0.1", 51000})
}

// readAll drains a reader into a string, for the stream-inspector tests.
func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read: %v", err)
	}
	return buf.String()
}
