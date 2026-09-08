// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/sshtest"
)

// TestIsAuthRejectionOnARealRejection is a TRIPWIRE, and it is the reason this
// classification is trustworthy at all.
//
// IsAuthRejection matches on the text golang.org/x/crypto/ssh builds when every
// authentication method was refused, because the library exports no typed error
// for it. A text match is only as good as the evidence that the text is still
// the text — so this drives a REAL rejection (a real handshake against a real
// in-process target that refuses the key) all the way through
// ssh.NewClientConn, and asserts on what comes back.
//
// Do NOT "simplify" it into a string equality check against a literal. A test
// that compares reject.go's constants to a copy of themselves would pass
// forever, including on the x/crypto upgrade that reworded the error — and the
// symptom of that upgrade is not a failing test, it is every refused credential
// silently going back to being reported as an unreachable target, retried
// without bound, with the breaker never scoring anything.
func TestIsAuthRejectionOnARealRejection(t *testing.T) {
	authorized := sshtest.MustGenerateSigner()
	tgt, err := sshtest.StartTarget(sshtest.Options{
		AuthorizedKeys: []ssh.PublicKey{authorized.PublicKey()},
	})
	if err != nil {
		t.Fatalf("start the target: %v", err)
	}
	defer func() { _ = tgt.Close() }()

	wrong := sshtest.MustGenerateSigner()
	_, err = dialWith(t, tgt, wrong)
	if err == nil {
		t.Fatal("the handshake succeeded with a key the target does not accept")
	}
	if !IsAuthRejection(err) {
		t.Fatalf("IsAuthRejection says no about a real refused credential.\n"+
			"x/crypto returned: %v\n"+
			"reject.go matches %q ... %q — if x/crypto reworded this, update BOTH and keep this test.",
			err, authRejectionPrefix, authRejectionSuffix)
	}

	// The other half of the tripwire: the key the target does accept must not
	// be classified as a rejection, or every session would score one.
	conn, err := dialWith(t, tgt, authorized)
	if err != nil {
		t.Fatalf("the handshake failed with the key the target accepts: %v", err)
	}
	_ = conn.Close()
}

// TestIsAuthRejectionIgnoresEverythingElse holds the classifier to being
// conservative: an outage mistaken for a rejection would withhold a credential
// that was never refused.
func TestIsAuthRejectionIgnoresEverythingElse(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"dial failure", errors.New("dial tcp 10.0.0.1:22: connect: connection refused")},
		{"reset", errors.New("read tcp 10.0.0.2:34: read: connection reset by peer")},
		{"host key", errors.New("ssh: handshake failed: host key mismatch")},
		{"partial success", errors.New("ssh: unable to authenticate, attempted methods [publickey], partial success")},
		{"unrelated remainder", errors.New("no supported methods remain")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if IsAuthRejection(tc.err) {
				t.Errorf("classified %v as a refused credential", tc.err)
			}
		})
	}
}

// dialWith runs one real client handshake against the target.
func dialWith(t *testing.T, tgt *sshtest.Target, signer ssh.Signer) (ssh.Conn, error) {
	t.Helper()
	addr := tgt.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial the target: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	client, _, _, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            "netadmin",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(tgt.HostKey()),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return client, nil
}

// TestDialOutcomeScoresOnlyRejections wires the seam the engine actually calls
// to the breaker, over a real handshake, so the two halves are held together
// rather than each being right on its own.
func TestDialOutcomeScoresOnlyRejections(t *testing.T) {
	authorized := sshtest.MustGenerateSigner()
	tgt, err := sshtest.StartTarget(sshtest.Options{
		AuthorizedKeys: []ssh.PublicKey{authorized.PublicKey()},
	})
	if err != nil {
		t.Fatalf("start the target: %v", err)
	}
	defer func() { _ = tgt.Close() }()

	breaker := NewRejectionBreaker(RejectionPolicy{Threshold: 2, Window: time.Minute, Cooldown: time.Minute})
	key := RejectionKey{Target: tgt.Addr().String(), Method: MethodBrokeredKey, Handle: "appliance-fleet"}
	access := &ProvisionedAccess{Credential: key, breaker: breaker}

	wrong := sshtest.MustGenerateSigner()
	_, err = dialWith(t, tgt, wrong)
	if err == nil {
		t.Fatal("the handshake succeeded with a key the target does not accept")
	}
	if state := access.DialOutcome(err); state.Consecutive != 1 || state.Open {
		t.Fatalf("first rejection: got %+v, want one consecutive and a closed breaker", state)
	}

	// A failure that is not a rejection is not evidence about the credential.
	if state := access.DialOutcome(errors.New("dial tcp: connect: connection refused")); state.Consecutive != 0 {
		t.Errorf("a dial failure was scored against the credential: %+v", state)
	}
	if err := breaker.Check(key); err != nil {
		t.Errorf("the breaker opened on a dial failure: %v", err)
	}

	_, err = dialWith(t, tgt, wrong)
	if err == nil {
		t.Fatal("the handshake succeeded with a key the target does not accept")
	}
	state := access.DialOutcome(err)
	if !state.Open || state.Consecutive != 2 {
		t.Fatalf("second rejection: got %+v, want the breaker open at two", state)
	}
	var withheld *WithheldError
	if err := breaker.Check(key); !errors.As(err, &withheld) || !errors.Is(err, ErrCredentialWithheld) {
		t.Fatalf("Check after the threshold returned %v, want a *WithheldError", err)
	}

	// A success closes it, which is what keeps a fixed credential from staying
	// withheld for the rest of the cooldown.
	conn, err := dialWith(t, tgt, authorized)
	if err != nil {
		t.Fatalf("the handshake failed with the key the target accepts: %v", err)
	}
	_ = conn.Close()
	access.DialOutcome(nil)
	if err := breaker.Check(key); err != nil {
		t.Errorf("the breaker stayed open after a success: %v", err)
	}
}
