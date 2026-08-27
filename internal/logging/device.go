// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
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
	if ev.Lifetime > 0 {
		attrs = attrs.Set(AttrLifetimeSeconds, strconv.Itoa(int(ev.Lifetime.Seconds())))
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

	d.shipper.RecordPriority(control.LogRecord{
		RecordID:   d.shipper.newRecordID(),
		Timestamp:  at(ev.At, d.shipper),
		Kind:       control.LogKindPolicyDecision,
		Severity:   control.SeverityCritical,
		Message:    "a device administrator this proxy created could not be removed",
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
