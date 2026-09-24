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

// TestAConfigChangeRidesTheBatchPath is the decision phase 0043 had to hold:
// the drift feed is several records per session, and on the priority path it
// would dilute the meaning PLAN §7 keeps that path for. The mapping event and
// a sweep failure stay where they were; this asserts both halves, because
// "the new record is batched" alone would pass on a change that also moved
// the old ones.
func TestAConfigChangeRidesTheBatchPath(t *testing.T) {
	shipper, server := newTestShipper(t, nil)
	sink := shipper.DeviceSink()

	sink.ConfigChange(target.DeviceConfigChange{
		Target: "fgt-1:22", Platform: "fortios", SessionID: "sess-1",
		Op: "create", Name: "hl-a1b2-alice-0f0f0f0f",
		Fields: map[string]string{"vdom": "root"},
	})
	sink.ConfigChange(target.DeviceConfigChange{
		Target: "fgt-1:22", Platform: "fortios",
		Op: "delete", ObjectKind: "firewall schedule", Name: "hl-a1b2-ghost-11111111",
	})
	sink.AccountMapping(target.AccountMapping{Account: "hl-a1b2-alice-0f0f0f0f", SessionID: "sess-1", Platform: "fortios",
		AlgorithmProfile: control.AlgorithmProfileLegacyDevice})
	sink.SweepFailure(target.SweepFailure{Target: "fgt-1:22", Platform: "fortios", Account: "hl-x", Reason: "refused"})

	eventually(t, func() bool { return len(server.priorityRecords()) == 2 }, "the mapping event and the sweep failure on the priority path")
	flush(t, shipper)
	for _, rec := range server.priorityRecords() {
		if rec.Attributes[AttrEvent] == EventDeviceConfigChange {
			t.Fatal("a configuration change reached the priority endpoint")
		}
		if rec.Attributes[AttrEvent] == "device.account.mapping" && rec.Attributes[AttrAlgorithmProfile] != "legacy-device" {
			t.Errorf("mapping event algorithm_profile = %q, want legacy-device", rec.Attributes[AttrAlgorithmProfile])
		}
	}

	var changes []control.LogRecord
	for _, rec := range server.batchedRecords() {
		if rec.Attributes[AttrEvent] == EventDeviceConfigChange {
			changes = append(changes, rec)
		}
	}
	if len(changes) != 2 {
		t.Fatalf("batched %d configuration changes, want 2", len(changes))
	}
	create, del := changes[0], changes[1]
	if create.Kind != control.LogKindProvisioning || create.Severity != control.SeverityInfo {
		t.Errorf("change record %s/%s, want provisioning/info", create.Kind, create.Severity)
	}
	if create.SessionID != "sess-1" || create.Target != "fgt-1:22" {
		t.Errorf("change record session %q target %q", create.SessionID, create.Target)
	}
	want := map[string]string{
		AttrPlatform: "fortios", AttrDeviceChangeOp: "create", AttrTargetAccount: "hl-a1b2-alice-0f0f0f0f",
		AttrDeviceFieldPrefix + "vdom": "root",
	}
	for k, v := range want {
		if create.Attributes[k] != v {
			t.Errorf("create record %s = %q, want %q", k, create.Attributes[k], v)
		}
	}
	if _, ok := create.Attributes[AttrDeviceObjectKind]; ok {
		t.Error("an administrator's change carries an object kind")
	}
	if del.Attributes[AttrDeviceObjectKind] != "firewall schedule" || del.Attributes[AttrDeviceChangeOp] != "delete" || del.SessionID != "" {
		t.Errorf("sweep's schedule removal recorded as %+v (session %q)", del.Attributes, del.SessionID)
	}
}

// TestExactlyOneNamePerFieldIsEmitted is the naming verdict held by a test
// rather than by a reviewer's grep (phase 0043): this proxy emits
// credential_method and credential_rung, and the other spelling of each —
// target_auth_method and target_auth_rung, which Hoplock Control's plan uses —
// is not an attribute key anywhere this package defines or its producers
// stamp.
func TestExactlyOneNamePerFieldIsEmitted(t *testing.T) {
	shipper, server := newTestShipper(t, nil)
	sink := shipper.DeviceSink()
	sink.AccountMapping(target.AccountMapping{Account: "hl-a", SessionID: "s", Platform: "fortios", Method: "ephemeral-account", Rung: 2})
	eventually(t, func() bool { return len(server.priorityRecords()) == 1 }, "the mapping event")
	attrs := server.priorityRecords()[0].Attributes
	if attrs[AttrCredentialMethod] != "ephemeral-account" || attrs[AttrCredentialRung] != "2" {
		t.Fatalf("mapping event method/rung = %q/%q", attrs[AttrCredentialMethod], attrs[AttrCredentialRung])
	}
	for _, other := range []string{"target_auth_method", "target_auth_rung"} {
		if _, ok := attrs[other]; ok {
			t.Errorf("the record also carries %q", other)
		}
	}
	if AttrCredentialMethod != "credential_method" || AttrCredentialRung != "credential_rung" {
		t.Errorf("the emitted names moved: %q, %q", AttrCredentialMethod, AttrCredentialRung)
	}
}
