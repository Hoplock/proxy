// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"sort"
	"strconv"
	"time"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/control"
)

// This file is where phase 0014's device events meet D8's transport, exactly as
// audit.go is where phase 0010's command-policy event does. It changes where
// each event goes, not what any field is called.

// DeviceSink returns the target.DeviceEventSink that routes the device method's
// events into the telemetry pipeline.
//
// It hangs off the Shipper rather than off a SessionRecorder because neither
// event is really a session's. The account-mapping event carries its session id
// as a FIELD — it has to, since on a constrained platform it is the only thing
// tying an eleven-character administrator name to a person — and a sweep failure
// belongs to no session at all: it is found by a background reaper, often long
// after the session that created the account has gone.
func (s *Shipper) DeviceSink() target.DeviceEventSink {
	if s == nil {
		return nil
	}
	return &deviceSink{shipper: s}
}

type deviceSink struct{ shipper *Shipper }

// Deliverable reports whether an event emitted now has somewhere to go.
//
// This is the predicate PLAN §5.3's fail-closed rule turns on: a route whose
// driver declares a constrained name limit is REFUSED when the proxy has no
// logging path at all, disk buffer included. So "the server is unreachable" is
// deliberately not the same answer as "there is nowhere to put this" — a
// buffered record is owed to the server, not lost, and refusing sessions during
// a Control outage on a proxy that is faithfully spooling to disk would be
// fail-closed against the wrong failure.
func (d *deviceSink) Deliverable() bool { return d.shipper.Deliverable() }

// AccountMapping records one account→identity mapping.
//
// It is CRITICAL, which is what puts it on D8's priority endpoint rather than
// in a batch. That is not a severity judgement about the event's contents: it is
// that on a constrained platform this record is the only attribution that
// exists, and a batch is a thing a crash loses.
func (d *deviceSink) AccountMapping(ev target.AccountMapping) {
	attrs := Attrs{}.
		Set(AttrEvent, "device.account.mapping").
		Set(AttrTargetAccount, ev.Account).
		Set(AttrPlatform, ev.Platform).
		Set(AttrCredentialMethod, ev.Method).
		Set(AttrExpiryPosture, ev.ExpiryPosture).
		Set(AttrAccessProfile, ev.Profile).
		SetBool(AttrNameConstrained, ev.Constrained).
		SetBool(AttrPersistsAcrossReload, ev.PersistsAcrossReload)
	if ev.Rung > 0 {
		attrs = attrs.Set(AttrCredentialRung, strconv.Itoa(ev.Rung))
	}
	attrs = EnforcementAttrs(attrs, ev.Enforcement)
	if ev.Lifetime > 0 {
		attrs = attrs.Set(AttrLifetimeSeconds, strconv.Itoa(int(ev.Lifetime.Seconds())))
	}
	// The route's platform-specific fields, spelled as the route spelled them.
	// On a partitioned device the target string names the unit and not the
	// partition, so without these the record cannot say what the administrator
	// was scoped to (PLAN §5.3).
	for _, name := range sortedKeys(ev.Fields) {
		attrs = attrs.Set(AttrDeviceFieldPrefix+name, ev.Fields[name])
	}
	if ev.ExpiryMechanism != "" {
		// Only on the sessions where the DEVICE holds the deadline, and it is
		// what stops `target-enforced` from being a word in the record that
		// nobody can cash: it says the unit refuses the next authentication,
		// that the account itself stays for the reaper, and that a session
		// already open may outlive the window.
		attrs = attrs.Set(AttrExpiryMechanism, ev.ExpiryMechanism)
	}
	if ev.PersistenceReason != "" {
		// The reason travels with the session it applies to, so that a
		// standing-account risk is recorded where the risk is taken rather than
		// only in a driver's source.
		attrs = attrs.Set(AttrPersistenceReason, ev.PersistenceReason)
	}

	rec := control.LogRecord{
		RecordID:   d.shipper.newRecordID(),
		SessionID:  ev.SessionID,
		Timestamp:  at(ev.At, d.shipper),
		Kind:       control.LogKindProvisioning,
		Severity:   control.SeverityCritical,
		Message:    "device administrator created for this session",
		Subject:    ev.Subject,
		Login:      ev.Login,
		Target:     ev.Target,
		Attributes: attrs,
	}
	d.shipper.RecordPriority(rec)
}

// sortedKeys orders a field map so one session's record is byte-identical
// however Go happened to iterate it. Log records are compared in tests and
// diffed by operators; map order would make both noisy.
func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// SweepFailure records an orphaned device account the reaper could not remove.
//
// It is CRITICAL for the reason D13 gives: where a platform cannot expire an
// account, the reaper is the only removal path there is, so a sweep that fails
// quietly leaves a live privileged administrator on a firewall and nobody finds
// out. This is the "somebody finds out".
func (d *deviceSink) SweepFailure(ev target.SweepFailure) {
	attrs := Attrs{}.
		Set(AttrEvent, "device.account.sweep_failed").
		Set(AttrPlatform, ev.Platform).
		Set(AttrTargetAccount, ev.Account).
		Set(AttrError, ev.Reason)

	// An administrator left behind and one of the objects that carried its
	// deadline left behind are not the same event, and the record says which.
	// The first is a standing privileged account on a firewall; the second
	// grants access to nothing. Both are reported because both are things this
	// proxy put on a customer's device and could not take off again, and
	// reporting the quieter one at the louder one's severity is how the louder
	// one stops being read.
	message := "a device administrator this proxy created could not be removed"
	if ev.ObjectKind != "" {
		attrs = attrs.Set(AttrDeviceObjectKind, ev.ObjectKind)
		message = "a device object this proxy created beside an account could not be removed"
	}

	d.shipper.RecordPriority(control.LogRecord{
		RecordID:   d.shipper.newRecordID(),
		Timestamp:  at(ev.At, d.shipper),
		Kind:       control.LogKindPolicyDecision,
		Severity:   control.SeverityCritical,
		Message:    message,
		Target:     ev.Target,
		Attributes: attrs,
	})
}

func at(t time.Time, s *Shipper) time.Time {
	if t.IsZero() {
		return s.now().UTC()
	}
	return t.UTC()
}

// EnforcementAttrs puts the rung IN FORCE on a record (contract v4's four
// fields plus this repository's operator half, PLAN §6.5).
//
// It is one function used by every producer — the session's provisioning record
// and the device method's mapping event — because the alternative is two
// spellings of the same claim that eventually disagree, with the disagreement
// landing in the audit trail rather than in a build failure.
func EnforcementAttrs(attrs Attrs, e *target.EnforcementResult) Attrs {
	if e == nil {
		return attrs
	}
	attrs = attrs.
		Set(AttrEnforcementExecution, string(e.Execution)).
		Set(AttrEnforcementReach, string(e.Reach)).
		SetBool(AttrEnforcementVerified, e.Verified)
	if e.AttestedBy != "" {
		attrs = attrs.Set(AttrEnforcementAttestedBy, e.AttestedBy)
	}
	if e.AttestationRef != "" {
		attrs = attrs.Set(AttrEnforcementAttestation, e.AttestationRef)
	}
	if e.ExecutionMechanism != "" {
		attrs = attrs.Set(AttrEnforcementMechanismExec, e.ExecutionMechanism)
	}
	if e.ReachMechanism != "" {
		attrs = attrs.Set(AttrEnforcementMechanismReach, e.ReachMechanism)
	}
	if e.Caveat != "" {
		attrs = attrs.Set(AttrEnforcementCaveat, e.Caveat)
	}
	return attrs
}
