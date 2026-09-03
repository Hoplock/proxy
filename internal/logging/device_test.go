// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"strings"
	"testing"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/control"
)

// TestTheMappingEventCarriesWhatTheDeviceEnforces is phase 0017's half of the
// account-mapping record.
//
// `expiry_posture` says WHO holds the deadline and cannot say what holding it
// buys: on FortiOS, as on OpenSSH's expiry-time, the device refuses the next
// authentication, leaves the account for the reaper, and says nothing about a
// session already open. A record carrying `target-enforced` alone would let a
// reviewer read a stronger guarantee out of it than the platform gives, which
// is the failure this attribute exists to prevent.
func TestTheMappingEventCarriesWhatTheDeviceEnforces(t *testing.T) {
	shipper, server := newTestShipper(t, nil)
	sink := shipper.DeviceSink()

	sink.AccountMapping(target.AccountMapping{
		Account:         "hl-a1b2-alice-0f0f0f0f",
		SessionID:       "sess-1",
		Platform:        "fortigate",
		ExpiryPosture:   string(control.ExpiryPostureTargetEnforced),
		ExpiryMechanism: "the device refuses the next authentication; the reaper still removes the account",
	})

	// The priority path is asynchronous: the record is queued here and shipped
	// by the shipper's own goroutine, so the assertion waits for delivery
	// rather than for a scheduling accident.
	eventually(t, func() bool { return len(server.priorityRecords()) == 1 }, "the mapping event to reach the priority endpoint")
	records := server.priorityRecords()
	attrs := records[0].Attributes
	if attrs[AttrExpiryPosture] != string(control.ExpiryPostureTargetEnforced) {
		t.Errorf("expiry_posture = %q", attrs[AttrExpiryPosture])
	}
	if !strings.Contains(attrs[AttrExpiryMechanism], "next authentication") {
		t.Errorf("expiry_mechanism = %q, want the driver's declaration verbatim", attrs[AttrExpiryMechanism])
	}
}

// TestASessionWithNoDeviceDeadlineClaimsNone is the same property from the
// other side: a proxy-enforced session renders nothing onto the device, so the
// record must not carry a claim about what the device enforces.
func TestASessionWithNoDeviceDeadlineClaimsNone(t *testing.T) {
	shipper, server := newTestShipper(t, nil)
	shipper.DeviceSink().AccountMapping(target.AccountMapping{
		Account:       "hl-a1b2-alice-0f0f0f0f",
		Platform:      "fortigate",
		ExpiryPosture: string(control.ExpiryPostureProxyEnforced),
	})

	eventually(t, func() bool { return len(server.priorityRecords()) == 1 }, "the mapping event to reach the priority endpoint")
	records := server.priorityRecords()
	if _, ok := records[0].Attributes[AttrExpiryMechanism]; ok {
		t.Error("a proxy-enforced session's record claims the device enforces something")
	}
}

// TestASweepFailureSaysWhichObjectWasLeftBehind separates the two failures a
// sweep can report.
//
// An administrator left behind is a standing privileged account on a firewall.
// A schedule left behind grants access to nothing. Both are reported, because
// both are objects this proxy put on somebody else's device and could not take
// off again — but reporting the quieter one as the louder one is how the louder
// one stops being read.
func TestASweepFailureSaysWhichObjectWasLeftBehind(t *testing.T) {
	shipper, server := newTestShipper(t, nil)
	sink := shipper.DeviceSink()

	sink.SweepFailure(target.SweepFailure{
		Target: "fgt-1:22", Platform: "fortigate",
		Account: "hl-a1b2-alice-0f0f0f0f", Reason: "the device refused the command",
	})
	sink.SweepFailure(target.SweepFailure{
		Target: "fgt-1:22", Platform: "fortigate",
		Account: "hl-a1b2-ghost-11111111", ObjectKind: "firewall schedule",
		Reason: "the device refused the command",
	})

	eventually(t, func() bool { return len(server.priorityRecords()) == 2 }, "both sweep failures to reach the priority endpoint")
	records := server.priorityRecords()
	if _, ok := records[0].Attributes[AttrDeviceObjectKind]; ok {
		t.Error("an administrator's sweep failure was labelled with an object kind")
	}
	if got := records[1].Attributes[AttrDeviceObjectKind]; got != "firewall schedule" {
		t.Errorf("device_object_kind = %q, want the object that was left behind", got)
	}
	if records[0].Message == records[1].Message {
		t.Error("the two failures read identically; an operator cannot tell a standing privileged account from a leftover schedule")
	}
	for _, rec := range records {
		if rec.Severity != control.SeverityCritical {
			t.Errorf("sweep failure severity %q: where the reaper is the only removal path, a quiet failure is the whole problem", rec.Severity)
		}
	}
}
