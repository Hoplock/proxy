// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package config

import (
	"errors"
	"strings"
	"testing"
)

// The disk buffer's window, logging.buffer_max_bytes (phase 0046, D8 as
// amended): bounded always, validated for operators, and the host's own budget
// rather than the fleet's.

func TestTheLogBufferWindowIsValidated(t *testing.T) {
	const base = `
proxy:
  id: "proxy-1"
  listen_addr: "0.0.0.0:2222"
  host_key_path: "/etc/hoplock/host_key"
control:
  base_url: "https://control.example.com"
auth:
  target:
    static_key:
      key_path: "/etc/hoplock/target_key"
logging:
  buffer_dir: "/var/lib/hoplock/proxy/logbuf"
`
	for _, tc := range []struct {
		name    string
		setting string
		want    int64
		refused bool
	}{
		// Absent is the package default of 1 GiB, which internal/logging
		// applies to a zero — as it does for every other logging knob.
		{name: "absent", want: 0},
		{name: "zero is the default", setting: "0", want: 0},
		{name: "the minimum", setting: "16777216", want: MinLogBufferBytes},
		{name: "a gibibyte", setting: "1073741824", want: 1 << 30},
		{name: "one byte under the minimum", setting: "16777215", refused: true},
		{name: "a window of one byte", setting: "1", refused: true},
		// There is no unbounded setting: an unbounded buffer is the defect.
		{name: "negative", setting: "-1", refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := base
			if tc.setting != "" {
				doc += "  buffer_max_bytes: " + tc.setting + "\n"
			}
			// Parse validates, so a refused value is refused there.
			cfg, err := Parse(strings.NewReader(doc))
			if !tc.refused {
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				if got := cfg.Logging.BufferMaxBytes; got != tc.want {
					t.Errorf("BufferMaxBytes = %d, want %d", got, tc.want)
				}
				return
			}
			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("Parse() = %v, want a ValidationError", err)
			}
			found := false
			for _, f := range verr.Fields {
				if f.Field == "logging.buffer_max_bytes" && errors.Is(f, ErrInvalid) {
					found = true
				}
			}
			if !found {
				t.Errorf("Parse() = %v, want logging.buffer_max_bytes refused as invalid", err)
			}
		})
	}
}

// TestTheLogBufferWindowIsBootstrap is D18 applied rather than re-derived: a
// setting is bootstrap until a phase lists it, and this one budgets the host's
// own disk — the material buffer_dir names — so it is not listed.
func TestTheLogBufferWindowIsBootstrap(t *testing.T) {
	for _, s := range FleetSettings() {
		if s.Key == "logging.buffer_max_bytes" {
			t.Fatalf("logging.buffer_max_bytes is fleet-owned (%+v); it names the host's own disk budget", s)
		}
	}
	cfg, err := Load(exampleConfigPath)
	if err != nil {
		t.Fatalf("Load(%s): %v", exampleConfigPath, err)
	}
	// The example states the default rather than leaving it implicit, so an
	// operator reads the number where they would change it.
	if got := cfg.Logging.BufferMaxBytes; got != 1<<30 {
		t.Errorf("the example's logging.buffer_max_bytes = %d, want 1 GiB", got)
	}
}
