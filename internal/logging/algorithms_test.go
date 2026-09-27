// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"testing"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/control"
)

// TestThePolicyInForceIsStampedOneWay pins phase 0045's absence rules: the
// profile always, the default included; the floor ONLY when there is one; one
// attribute per banned axis, its names sorted, and none for an axis with no ban.
func TestThePolicyInForceIsStampedOneWay(t *testing.T) {
	plain := AlgorithmPolicyAttrs(Attrs{}, control.AlgorithmPolicy{})
	if plain[AttrAlgorithmProfile] != "default" {
		t.Errorf("algorithm_profile = %q, want default stamped", plain[AttrAlgorithmProfile])
	}
	for key := range plain {
		if key != AttrAlgorithmProfile {
			t.Errorf("a policy with no floor and no ban stamped %q", key)
		}
	}

	full := AlgorithmPolicyAttrs(Attrs{}, control.AlgorithmPolicy{
		Profile: control.AlgorithmProfileLegacyRSASHA1,
		Floor:   control.AlgorithmFloorPQHybridKEX,
		Bans:    &control.AlgorithmBans{Ciphers: []string{"aes256-ctr", "aes128-ctr"}, HostKeys: []string{"ssh-rsa"}},
	})
	for key, want := range map[string]string{
		AttrAlgorithmProfile:                  "legacy-rsa-sha1",
		AttrAlgorithmFloor:                    "pq-hybrid-kex",
		AttrAlgorithmBansPrefix + "ciphers":   "aes128-ctr,aes256-ctr",
		AttrAlgorithmBansPrefix + "host_keys": "ssh-rsa",
	} {
		if got := full[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	for _, empty := range []string{"key_exchanges", "macs", "public_key_auth"} {
		if _, present := full[AttrAlgorithmBansPrefix+empty]; present {
			t.Errorf("an axis with no ban stamped algorithm_bans.%s", empty)
		}
	}
}

// TestTheDeviceEventsCarryThePolicyAndTheExchange: the mapping event — on a
// constrained device the only record there is — names the floor, the bans and
// the exchange the driver's own connection negotiated; a sweep that could not
// agree an algorithm names the axis and what the device offers now.
func TestTheDeviceEventsCarryThePolicyAndTheExchange(t *testing.T) {
	shipper, server := newTestShipper(t, nil)
	sink := shipper.DeviceSink()
	sink.AccountMapping(target.AccountMapping{Account: "hl-a", SessionID: "s", Platform: "fortios",
		AlgorithmProfile: control.AlgorithmProfileDefault, AlgorithmFloor: control.AlgorithmFloorModernKEX,
		AlgorithmBans: &control.AlgorithmBans{MACs: []string{"hmac-sha1"}}, KexAlgorithm: "curve25519-sha256"})
	sink.SweepFailure(target.SweepFailure{Target: "fw:22", Platform: "fortios", Reason: "changed",
		AlgorithmAxis: "key_exchange", AlgorithmsOffered: []string{"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"}})
	eventually(t, func() bool { return len(server.priorityRecords()) == 2 }, "the two device events")

	mapping, sweep := server.priorityRecords()[0].Attributes, server.priorityRecords()[1].Attributes
	for key, want := range map[string]string{
		AttrAlgorithmProfile:             "default",
		AttrAlgorithmFloor:               "modern-kex",
		AttrAlgorithmBansPrefix + "macs": "hmac-sha1",
		AttrTargetKexAlgorithm:           "curve25519-sha256",
	} {
		if got := mapping[key]; got != want {
			t.Errorf("mapping event %s = %q, want %q", key, got, want)
		}
	}
	if sweep[AttrAlgorithmAxis] != "key_exchange" ||
		sweep[AttrTargetAlgorithmsOffered] != "diffie-hellman-group14-sha1,diffie-hellman-group1-sha1" {
		t.Errorf("sweep failure = %+v, want the axis and what the device offers", sweep)
	}

	// A mapping event whose driver could not say what it negotiated omits the
	// exchange rather than stamping an empty one.
	sink.AccountMapping(target.AccountMapping{Account: "hl-b", SessionID: "s2", Platform: "fortios",
		AlgorithmProfile: control.AlgorithmProfileDefault})
	eventually(t, func() bool { return len(server.priorityRecords()) == 3 }, "the second mapping event")
	if _, present := server.priorityRecords()[2].Attributes[AttrTargetKexAlgorithm]; present {
		t.Error("a mapping event with no negotiated exchange stamped target_kex_algorithm")
	}
}
