// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/sshtest"
)

// nextHopRoute builds an authorize hook answering with a next-hop route, so a
// test can vary just the hop metadata.
func nextHopRoute(hop *control.HopMetadata) func(*control.AuthorizeRequest) (*control.AuthorizeResponse, error) {
	return func(req *control.AuthorizeRequest) (*control.AuthorizeResponse, error) {
		return &control.AuthorizeResponse{
			RouteType:         control.RouteTypeNextHop,
			Target:            "next-proxy.invalid",
			TargetPort:        22,
			Permissions:       "testGroup",
			PermittedChannels: []string{channelSession},
			FilterPolicy:      control.FilterPolicy{Mode: control.FilterModeBlacklist},
			Hop:               hop,
			DecisionID:        "decision-1",
		}, nil
	}
}

// failingOpener records that it was asked and refuses, standing in for a hub
// with no registration for the id.
type failingOpener struct {
	asked []string
	err   error
}

func (o *failingOpener) Open(_ context.Context, proxyID string) (net.Conn, error) {
	o.asked = append(o.asked, proxyID)
	return nil, o.err
}

// TestRelayHopWithoutRegistrationIsAnOutage is D11's refusal rule: a relay hop
// whose next proxy is not connected fails as an outage naming the session, and
// is never quietly dialled instead — dialling is the boundary the mode exists
// to preserve.
func TestRelayHopWithoutRegistrationIsAnOutage(t *testing.T) {
	opener := &failingOpener{err: errors.New("no proxy is registered under that id")}
	h := newHarness(t, harnessOptions{
		authorize: nextHopRoute(&control.HopMetadata{
			Connection:  control.HopConnectionRelay,
			NextProxyID: "proxy-enclave",
			FinalTarget: "deep.internal.example.com",
		}),
		options: func(o *Options) {
			o.HopSigner = sshtest.MustGenerateSigner()
			o.RelayOpener = opener
		},
	})

	text, status := runAndCollect(t, h, "uptime")

	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, want an outage rather than a denial", text)
	}
	if !strings.Contains(text, testSessionID) {
		t.Errorf("user saw %q, want the session id as a support reference", text)
	}
	if !strings.Contains(text, "not currently connected") {
		t.Errorf("user saw %q, want it to say the next proxy is not connected", text)
	}
	if status == 0 {
		t.Error("a session that never reached its target exited 0")
	}
	if got, want := opener.asked, []string{"proxy-enclave"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("relay opener asked for %v, want %v", got, want)
	}
	if strings.Contains(h.logs.String(), "next-proxy.invalid") {
		t.Errorf("the engine touched the dial address of a relay hop; logs:\n%s", h.logs.String())
	}
}

// TestRelayHopWithoutARelayOpener covers a proxy that accepts no registrations
// at all being handed a relay route: still an outage, still never a dial.
func TestRelayHopWithoutARelayOpener(t *testing.T) {
	h := newHarness(t, harnessOptions{
		authorize: nextHopRoute(&control.HopMetadata{
			Connection:  control.HopConnectionRelay,
			NextProxyID: "proxy-enclave",
			FinalTarget: "deep.internal.example.com",
		}),
		options: func(o *Options) { o.HopSigner = sshtest.MustGenerateSigner() },
	})

	text, _ := runAndCollect(t, h, "uptime")

	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, want an outage rather than a denial", text)
	}
	if !strings.Contains(text, "not currently connected") {
		t.Errorf("user saw %q, want it to name the missing registration", text)
	}
}

// TestHopLoopIsRefusedAndAudited covers a route that sends the session back to
// a proxy already in the chain — here, straight back to this one.
func TestHopLoopIsRefusedAndAudited(t *testing.T) {
	h := newHarness(t, harnessOptions{
		authorize: nextHopRoute(&control.HopMetadata{
			NextProxyID: testProxyID,
			FinalTarget: "deep.internal.example.com",
		}),
		options: func(o *Options) { o.HopSigner = sshtest.MustGenerateSigner() },
	})

	text, status := runAndCollect(t, h, "uptime")

	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, want an outage rather than a denial", text)
	}
	if !strings.Contains(text, "chain of proxies") {
		t.Errorf("user saw %q, want it to name the chain", text)
	}
	if status == 0 {
		t.Error("a looping route exited 0")
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "audit=hop_refused") {
		t.Errorf("no audit event for the refused loop; logs:\n%s", logs)
	}
	if !strings.Contains(logs, "already in") {
		t.Errorf("the audit event does not say the chain loops; logs:\n%s", logs)
	}
}

// TestHopLimitIsRefusedAndAudited covers the hop cap: the server's own cap of
// one hop is already spent by this proxy, so extending the chain is refused.
func TestHopLimitIsRefusedAndAudited(t *testing.T) {
	h := newHarness(t, harnessOptions{
		authorize: nextHopRoute(&control.HopMetadata{
			NextProxyID: "proxy-b",
			FinalTarget: "deep.internal.example.com",
			MaxHops:     1,
		}),
		options: func(o *Options) { o.HopSigner = sshtest.MustGenerateSigner() },
	})

	text, _ := runAndCollect(t, h, "uptime")

	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, want an outage rather than a denial", text)
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "audit=hop_refused") {
		t.Errorf("no audit event for the exceeded hop count; logs:\n%s", logs)
	}
	if !strings.Contains(logs, "the limit is 1") {
		t.Errorf("the audit event does not name the limit; logs:\n%s", logs)
	}
}

// TestNextHopWithoutAChainIdentityIsAnOutage covers a proxy that was never
// given a key to present to another proxy: it cannot extend a chain, and says
// so as a service limitation rather than as a denial.
func TestNextHopWithoutAChainIdentityIsAnOutage(t *testing.T) {
	h := newHarness(t, harnessOptions{
		authorize: nextHopRoute(&control.HopMetadata{
			NextProxyID: "proxy-b",
			FinalTarget: "deep.internal.example.com",
		}),
	})

	text, _ := runAndCollect(t, h, "uptime")

	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, want an outage rather than a denial", text)
	}
	if !strings.Contains(text, testSessionID) {
		t.Errorf("user saw %q, want the session id as a support reference", text)
	}
}
