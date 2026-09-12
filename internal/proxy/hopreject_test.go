// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/logging"
	"github.com/hoplock/proxy/internal/sshtest"
)

// This file is the chain leg's half of prompt 0033, and it is deliberately the
// mirror of reject_test.go: a NEXT PROXY that refuses this proxy's chain
// identity key (D11) is classified as its own failure, told to the user as an
// outage that discloses nothing about the far hop or the key, and recorded as a
// critical event.
//
// As there, the far side is a real SSH server that really refuses the key we
// offer it. The classification is a text match on what x/crypto produces, so a
// stubbed error would only be asserting on our own copy of it.

// refusingHop starts a stand-in next proxy that accepts one key, and returns
// the DIFFERENT key this proxy will present to it.
func refusingHop(t *testing.T) (*sshtest.Target, ssh.Signer) {
	t.Helper()
	accepted := sshtest.MustGenerateSigner()
	hop, err := sshtest.StartTarget(sshtest.Options{AuthorizedKeys: []ssh.PublicKey{accepted.PublicKey()}})
	if err != nil {
		t.Fatalf("StartTarget: %v", err)
	}
	t.Cleanup(func() { _ = hop.Close() })
	return hop, sshtest.MustGenerateSigner()
}

// hopRouteTo answers with a next-hop route reaching a named address, so a test
// can point a chain leg at a server it started itself.
func hopRouteTo(host string, port int, hop *control.HopMetadata) func(*control.AuthorizeRequest) (*control.AuthorizeResponse, error) {
	return func(*control.AuthorizeRequest) (*control.AuthorizeResponse, error) {
		return &control.AuthorizeResponse{
			RouteType:         control.RouteTypeNextHop,
			Target:            host,
			TargetPort:        port,
			Permissions:       "testGroup",
			PermittedChannels: []string{channelSession},
			FilterPolicy:      control.FilterPolicy{Mode: control.FilterModeBlacklist},
			Hop:               hop,
			DecisionID:        "decision-1",
		}, nil
	}
}

// dialingOpener stands in for a relay hub whose registration reaches a proxy
// that refuses us. It is what makes the relay direction testable at all: the
// engine only ever sees a net.Conn, so the byte stream can come from a socket
// this test dialled rather than from a registration.
type dialingOpener struct {
	addr  string
	asked []string
}

func (o *dialingOpener) Open(ctx context.Context, proxyID string) (net.Conn, error) {
	o.asked = append(o.asked, proxyID)
	var d net.Dialer
	return d.DialContext(ctx, "tcp", o.addr)
}

// TestARefusedChainIdentityIsNotReportedAsAnUnreachableProxy is the defect
// phase 0025 found one function away from its own and left alone, stated as a
// test.
//
// The next proxy is up and answering; what it refused is this proxy's chain
// identity key. Told "the next proxy in the chain could not be reached", the
// operator is sent to look at the network — the one part of the estate that is
// working.
func TestARefusedChainIdentityIsNotReportedAsAnUnreachableProxy(t *testing.T) {
	hop, held := refusingHop(t)
	h := newHarness(t, harnessOptions{
		authorize: hopRouteTo(hop.Host(), hop.Port(), &control.HopMetadata{
			NextProxyID: "proxy-b",
			FinalTarget: "deep.internal.example.com",
		}),
		options: func(o *Options) { o.HopSigner = held },
	})

	text, status := runAndCollect(t, h, "uptime")

	if status == 0 {
		t.Error("a session whose chain identity was refused exited 0")
	}
	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q; a refused CHAIN identity is an outage, not the user's permissions", text)
	}
	if strings.Contains(text, "could not be reached") {
		t.Errorf("user saw %q; the next proxy was reached and refused us", text)
	}
	if !strings.Contains(text, "not accepted by the next proxy in the chain") {
		t.Errorf("user saw %q, want it to say this proxy was not accepted", text)
	}
	if !strings.Contains(text, testSessionID) {
		t.Errorf("user saw %q, want the session id as the support reference (PLAN §4.3)", text)
	}

	// It discloses nothing about the far hop or the key: not the proxy id, not
	// the address it lives at, not the fingerprint, and not how far along the
	// chain the session got.
	for _, leak := range []string{
		"proxy-b", hop.Host() + ":" + strconv.Itoa(hop.Port()), "SHA256:", testProxyID,
	} {
		if strings.Contains(text, leak) {
			t.Errorf("user saw %q, which discloses %q about the chain (PLAN §4.3)", text, leak)
		}
	}
}

// TestARefusedChainIdentityIsRecordedCritically covers the audit half: the
// event an operator has to act on does not wait in a batch, and it names the
// key by FINGERPRINT and by nothing else.
func TestARefusedChainIdentityIsRecordedCritically(t *testing.T) {
	hop, held := refusingHop(t)
	h := newHarness(t, harnessOptions{
		authorize: hopRouteTo(hop.Host(), hop.Port(), &control.HopMetadata{
			Connection:  control.HopConnectionDial,
			NextProxyID: "proxy-b",
			FinalTarget: "deep.internal.example.com",
		}),
		options: func(o *Options) { o.HopSigner = held },
	})
	runAndCollect(t, h, "uptime")

	rec, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Attributes[logging.AttrEvent] == "chain.identity_rejected"
	})
	if !ok {
		t.Fatal("a refused chain identity produced no record")
	}
	if rec.Kind != control.LogKindError {
		t.Errorf("record kind = %s, want %s", rec.Kind, control.LogKindError)
	}
	if rec.Severity != control.SeverityCritical {
		t.Errorf("record severity = %s, want critical so it takes D8's immediate path", rec.Severity)
	}
	if !recordedOnPriorityPath(h, rec.RecordID) {
		t.Error("the record waited in a batch; a critical record takes the priority path (D8)")
	}
	if rec.Attributes[logging.AttrHopNextProxy] != "proxy-b" {
		t.Errorf("record next proxy = %q, want proxy-b", rec.Attributes[logging.AttrHopNextProxy])
	}
	if got := rec.Attributes[logging.AttrHopConnection]; got != string(control.HopConnectionDial) {
		t.Errorf("record hop direction = %q, want %q", got, control.HopConnectionDial)
	}
	if rec.Attributes[logging.AttrStage] != string(stageHopAuth) {
		t.Errorf("record stage = %q, want %q", rec.Attributes[logging.AttrStage], stageHopAuth)
	}
	want := ssh.FingerprintSHA256(held.PublicKey())
	if got := rec.Attributes[logging.AttrCredentialHandle]; got != want {
		t.Errorf("record credential handle = %q, want the chain key's fingerprint %q", got, want)
	}
}

// TestNoChainRecordCarriesKeyMaterial is the rule that is invisible in a diff:
// the handle is a fingerprint, and nothing anywhere on these records is a key
// or a path to one.
func TestNoChainRecordCarriesKeyMaterial(t *testing.T) {
	hop, held := refusingHop(t)
	h := newHarness(t, harnessOptions{
		authorize: hopRouteTo(hop.Host(), hop.Port(), &control.HopMetadata{
			NextProxyID: "proxy-b",
			FinalTarget: "deep.internal.example.com",
		}),
		options: func(o *Options) { o.HopSigner = held },
	})
	runAndCollect(t, h, "uptime")

	marshalled := string(ssh.MarshalAuthorizedKey(held.PublicKey()))
	for _, rec := range h.records() {
		for key, value := range rec.Attributes {
			if strings.Contains(value, "PRIVATE KEY") || strings.Contains(value, "BEGIN OPENSSH") {
				t.Errorf("record attribute %s carries key material", key)
			}
			if strings.Contains(value, strings.TrimSpace(marshalled)) {
				t.Errorf("record attribute %s carries the chain identity key itself", key)
			}
		}
		if strings.Contains(rec.Message, "PRIVATE KEY") {
			t.Errorf("record message carries key material: %s", rec.Message)
		}
	}
}

// TestAHopHostKeyFailureStillWinsOverTheRejectionBranch keeps the ordering the
// prompt calls out, and it is the same ordering dialTarget has.
//
// Both failures are live at once: the next proxy would refuse this key AND this
// proxy refuses its host key. Ordered the other way round, a host key nobody
// trusts would be reported as a refused chain identity — a different fault with
// a different fix, and one that would send an operator to register a key that
// is already registered.
func TestAHopHostKeyFailureStillWinsOverTheRejectionBranch(t *testing.T) {
	hop, held := refusingHop(t)
	h := newHarness(t, harnessOptions{
		authorize: hopRouteTo(hop.Host(), hop.Port(), &control.HopMetadata{
			NextProxyID: "proxy-b",
			FinalTarget: "deep.internal.example.com",
		}),
		hostKey: func(*control.HostKeyReportRequest) (*control.HostKeyReportResponse, error) {
			return &control.HostKeyReportResponse{Decision: control.HostKeyReject, Reason: "unknown key"}, nil
		},
		options: func(o *Options) { o.HopSigner = held },
	})

	text, _ := runAndCollect(t, h, "uptime")

	if !strings.Contains(text, "host key was not accepted") {
		t.Errorf("user saw %q, want the host-key failure", text)
	}
	if strings.Contains(text, "not accepted by the next proxy in the chain") {
		t.Errorf("user saw %q; a host-key failure was classified as a refused chain identity", text)
	}
	for _, rec := range h.records() {
		if rec.Attributes[logging.AttrEvent] == "chain.identity_rejected" {
			t.Error("a host-key failure produced a chain.identity_rejected record")
		}
	}
}

// TestARefusedChainIdentityOnARelayHopIsClassifiedTheSameWay covers the other
// connection direction (D11).
//
// The classification lives after the transport is open, so it is direction-
// agnostic by construction — and that is worth holding: a relay hop reaches the
// far proxy over a registration the DOWNSTREAM proxy opened, so a refusal there
// is the same fact about the same key, and the record has to say which
// direction it happened on.
func TestARefusedChainIdentityOnARelayHopIsClassifiedTheSameWay(t *testing.T) {
	hop, held := refusingHop(t)
	opener := &dialingOpener{addr: net.JoinHostPort(hop.Host(), strconv.Itoa(hop.Port()))}
	h := newHarness(t, harnessOptions{
		authorize: hopRouteTo("proxy-enclave.invalid", 22, &control.HopMetadata{
			Connection:  control.HopConnectionRelay,
			NextProxyID: "proxy-enclave",
			FinalTarget: "deep.internal.example.com",
		}),
		options: func(o *Options) {
			o.HopSigner = held
			o.RelayOpener = opener
		},
	})

	text, _ := runAndCollect(t, h, "uptime")

	if !strings.Contains(text, "not accepted by the next proxy in the chain") {
		t.Errorf("user saw %q, want the refusal classified the same way on a relay hop", text)
	}
	if strings.Contains(text, "not currently connected") {
		t.Errorf("user saw %q; the registration WAS live and the far proxy refused us", text)
	}
	if len(opener.asked) != 1 || opener.asked[0] != "proxy-enclave" {
		t.Errorf("relay opener asked for %v, want one channel to proxy-enclave", opener.asked)
	}

	rec, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Attributes[logging.AttrEvent] == "chain.identity_rejected"
	})
	if !ok {
		t.Fatal("a refused chain identity on a relay hop produced no record")
	}
	if got := rec.Attributes[logging.AttrHopConnection]; got != string(control.HopConnectionRelay) {
		t.Errorf("record hop direction = %q, want %q", got, control.HopConnectionRelay)
	}
}
