// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
	"github.com/hoplock/proxy/internal/logging"
	"github.com/hoplock/proxy/internal/sshtest"
)

// This file is the engine's half of phase 0027. The allocator itself is
// `internal/auth/target`'s; what is asserted here is the one thing only the
// engine can get wrong: a proxy that cannot allocate a non-reusing uid must
// REFUSE the session as an outage, and the sentence the user is shown must
// disclose nothing about the target.

// unallocatableAuth is a target authenticator whose uid allocation always
// refuses. It stands in for the two real causes — an exhausted range, and a
// target whose uid census could not be read — because the engine's behaviour is
// the same for both and neither is reachable from here without a target.
type unallocatableAuth struct{}

func (unallocatableAuth) Name() string { return target.MethodEphemeralUser }

func (unallocatableAuth) Provision(context.Context, *identity.Identity, target.Target) (*target.ProvisionedAccess, error) {
	return nil, fmt.Errorf("%w: the range 2000000-2000001 is exhausted on this target, and allocation does not wrap",
		target.ErrUIDUnavailable)
}

// TestAnUnallocatableUIDIsAnOutageAndNotADenial is the fail-closed requirement.
//
// The user cannot fix this with a different credential — nothing about their
// permissions is in question — so it must not wear the denial message, and the
// session must not be served on a recycled uid instead.
func TestAnUnallocatableUIDIsAnOutageAndNotADenial(t *testing.T) {
	h := newHarness(t, harnessOptions{targetAuth: unallocatableAuth{}})

	text, status := runAndCollect(t, h, "uptime")

	if status == 0 {
		t.Error("a session that could not be given an isolated account exited 0")
	}
	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q; this is an outage, not a decision about the user's permissions", text)
	}
	if !strings.Contains(text, "isolated account") {
		t.Errorf("user saw %q, want it to name the guarantee that could not be met", text)
	}
	if !strings.Contains(text, testSessionID) {
		t.Errorf("user saw %q, want the session id as the support reference (PLAN §4.3)", text)
	}
}

// TestAnUnallocatableUIDDisclosesNothingAboutTheTarget is PLAN §4.3 on the new
// stage. An outage message that named the range, the host, or the account would
// be an estate map handed out one refused session at a time.
func TestAnUnallocatableUIDDisclosesNothingAboutTheTarget(t *testing.T) {
	h := newHarness(t, harnessOptions{targetAuth: unallocatableAuth{}})

	text, _ := runAndCollect(t, h, "uptime")

	host, _ := h.targetHostPort()
	for _, leak := range []string{host, "2000000", "uid", "exhausted", "wrap"} {
		if strings.Contains(text, leak) {
			t.Errorf("user saw %q, which discloses %q", text, leak)
		}
	}
}

// TestAnUnallocatableUIDIsItsOwnStage keeps 0025's seam honest. "Credentials
// could not be provisioned" sends an operator to the provisioning account on the
// target; nothing on the target failed, and the fix is this proxy's uid range.
func TestAnUnallocatableUIDIsItsOwnStage(t *testing.T) {
	err := (&session{}).provisionError(fmt.Errorf("%w: exhausted", target.ErrUIDUnavailable))
	var se *setupError
	if !errors.As(err, &se) {
		t.Fatalf("provisionError returned %v, want a setupError", err)
	}
	if se.stage != stageProvisionUID {
		t.Fatalf("stage = %q, want %q", se.stage, stageProvisionUID)
	}
	if got := outageDetail(err); got != "the target could not be given an isolated account for this session" {
		t.Errorf("outage detail = %q", got)
	}
}

// uidReportingAuth is the static-key placeholder with a uid attached, standing in
// for the ephemeral provisioner: the session really connects, and the access
// reports the numeric identity of the account it connected as.
type uidReportingAuth struct {
	inner target.TargetAuthenticator
	uid   int
}

func (a uidReportingAuth) Name() string { return target.MethodEphemeralUser }

func (a uidReportingAuth) Provision(ctx context.Context, id *identity.Identity, tgt target.Target) (*target.ProvisionedAccess, error) {
	access, err := a.inner.Provision(ctx, id, tgt)
	if err != nil {
		return nil, err
	}
	access.AccountUID = a.uid
	return access, nil
}

// TestTheProvisioningRecordCarriesTheAccountUID is prompt 0027 §3.
//
// The account NAME is deleted at teardown, so a record holding only the name
// leaves an incident responder with a join key that names nothing: the uid is
// what `find -uid`, the target's own auditd, and every file the session left
// outside its home actually speak.
func TestTheProvisioningRecordCarriesTheAccountUID(t *testing.T) {
	const uid = 2000004
	placeholder, err := target.NewStaticKeyAuthenticator(target.StaticKeyOptions{Signer: sshtest.MustGenerateSigner(), Username: testTargetAccount})
	if err != nil {
		t.Fatalf("NewStaticKeyAuthenticator: %v", err)
	}
	h := newHarness(t, harnessOptions{
		targetAuth:    uidReportingAuth{inner: placeholder, uid: uid},
		targetOptions: sshtest.Options{},
	})

	runAndCollect(t, h, "uptime")

	rec, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Kind == control.LogKindProvisioning && r.Attributes[logging.AttrTargetAccount] != ""
	})
	if !ok {
		t.Fatal("no provisioning record named an account")
	}
	if got := rec.Attributes[logging.AttrTargetAccountUID]; got != strconv.Itoa(uid) {
		t.Errorf("record %s = %q, want %q", logging.AttrTargetAccountUID, got, strconv.Itoa(uid))
	}
	for _, value := range rec.Attributes {
		if strings.Contains(value, "PRIVATE KEY") {
			t.Errorf("the provisioning record carries key material: %v", rec.Attributes)
		}
	}
}
