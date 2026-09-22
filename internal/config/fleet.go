// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// This file is the bootstrap/fleet line of PLAN D18.
//
// A setting is BOOTSTRAP — settable only in this host's YAML file — unless it is
// in fleetSettings below. The rule that decides whether it MAY be moved there:
// a setting stays bootstrap if the proxy needs it to reach Hoplock Control at
// all, or to be recognised by it (control.base_url, control.token, proxy.id); if
// it names material on this host (a key, a certificate, a directory, an
// environment variable); if it binds a listener (proxy.listen_addr,
// chain.accept.listen_addr); or if it is the proxy's own judgement of whether it
// can still hear Control (control.cache.stale_after — the one thing Control
// cannot vouch for about itself). A proxy that could be told any of those
// remotely is one a bad document can orphan with no channel left to fix it
// over.
//
// Everything else is a CANDIDATE, and it becomes fleet-owned only by being
// listed here, in the same PR that updates PLAN D18 and marks it in
// config.example.yaml. A new setting is therefore bootstrap until somebody
// decides otherwise — the default a fleet document cannot widen by accident.

// FleetSetting describes one fleet-owned setting.
type FleetSetting struct {
	// Key is the setting's dotted bootstrap key, exactly as a fleet document
	// names it (e.g. "control.cache.max_ttl").
	Key string
	// Live is true when a running proxy applies a change to it without a
	// restart. A document changing any setting that is not Live is held until
	// the process restarts, and is never reported as running before then.
	Live bool

	set func(*Config, json.RawMessage) error
	get func(*Config) any
}

// fleetSettings is the whole of what a fleet document may set, in key order.
var fleetSettings = []FleetSetting{
	fleetDuration("auth.user.mfa.max_wait", false, func(c *Config) *time.Duration { return &c.Auth.User.MFA.MaxWait }),
	fleetDuration("auth.user.mfa.min_poll_interval", false, func(c *Config) *time.Duration { return &c.Auth.User.MFA.MinPollInterval }),
	fleetDuration("auth.user.mfa.progress_interval", false, func(c *Config) *time.Duration { return &c.Auth.User.MFA.ProgressInterval }),
	fleetInt("chain.max_hops", false, func(c *Config) *int { return &c.Chain.MaxHops }),
	fleetString("chain.upstream.address", false, func(c *Config) *string { return &c.Chain.Upstream.Address }),
	fleetInt("control.cache.max_entries", false, func(c *Config) *int { return &c.Control.Cache.MaxEntries }),
	fleetDuration("control.cache.max_ttl", true, func(c *Config) *time.Duration { return &c.Control.Cache.MaxTTL }),
	fleetInt("dial.default_target_port", false, func(c *Config) *int { return &c.Dial.DefaultTargetPort }),
	fleetDuration("dial.dial_timeout", false, func(c *Config) *time.Duration { return &c.Dial.DialTimeout }),
	fleetInt("logging.batch_size", false, func(c *Config) *int { return &c.Logging.BatchSize }),
	fleetDuration("logging.flush_interval", false, func(c *Config) *time.Duration { return &c.Logging.FlushInterval }),
	fleetInt("logging.max_payload_bytes", false, func(c *Config) *int { return &c.Logging.MaxPayloadBytes }),
	fleetInt("logging.queue_size", false, func(c *Config) *int { return &c.Logging.QueueSize }),
	fleetDuration("logging.retry_max", false, func(c *Config) *time.Duration { return &c.Logging.RetryMax }),
	fleetDuration("logging.retry_min", false, func(c *Config) *time.Duration { return &c.Logging.RetryMin }),
	fleetDuration("logging.send_timeout", false, func(c *Config) *time.Duration { return &c.Logging.SendTimeout }),
	fleetDuration("session.deadline_warning", true, func(c *Config) *time.Duration { return &c.Session.DeadlineWarning }),
}

// FleetSettings returns every fleet-owned setting, in key order.
func FleetSettings() []FleetSetting { return slices.Clone(fleetSettings) }

// FleetSettingFor returns the fleet-owned setting named key.
func FleetSettingFor(key string) (FleetSetting, bool) {
	for _, s := range fleetSettings {
		if s.Key == key {
			return s, true
		}
	}
	return FleetSetting{}, false
}

// ErrNotFleetOwned rejects a fleet document that names a setting it may not set:
// a bootstrap setting, or one that does not exist.
var ErrNotFleetOwned = errors.New("not a fleet-owned setting")

// WithFleet returns a copy of c with a fleet document's settings applied, and
// validated as a whole. c itself is never modified.
//
// It is all or nothing: a key that is not fleet-owned, a value of the wrong
// type, or a result that fails Validate rejects the entire document, and every
// problem is reported at once. Error text names keys, never values.
//
// nil or empty settings yields c's own values — the bootstrap file alone.
func (c *Config) WithFleet(settings map[string]json.RawMessage) (*Config, error) {
	out := *c // shallow: only scalar fleet-owned fields are written below
	var v ValidationError
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s, ok := FleetSettingFor(k)
		if !ok {
			v.add(k, ErrNotFleetOwned, "a fleet document may set only the settings listed in PLAN D18; this one is bootstrap-only or unknown")
			continue
		}
		if err := s.set(&out, settings[k]); err != nil {
			v.add(k, ErrInvalid, err.Error())
		}
	}
	if len(v.Fields) > 0 {
		return nil, &v
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return &out, nil
}

// FleetRestartRequired lists the settings that differ between a process's
// started configuration and next and cannot be applied without a restart.
func FleetRestartRequired(started, next *Config) []string {
	var keys []string
	for _, s := range fleetSettings {
		if !s.Live && s.get(started) != s.get(next) {
			keys = append(keys, s.Key)
		}
	}
	return keys
}

// Fleet applies fleet documents to a running process (PLAN D18). It implements
// control.ConfigApplier without importing it.
type Fleet struct {
	bootstrap *Config
	started   *Config
	live      func(*Config)

	mu      sync.Mutex
	current *Config
}

// NewFleet builds the applier. bootstrap is the host's file; started is what the
// process's components were built from (bootstrap, or bootstrap with the
// document fetched at startup); live is called with the new effective
// configuration whenever a document is applied, and must push every Live
// setting into the component that reads it.
func NewFleet(bootstrap, started *Config, live func(*Config)) *Fleet {
	return &Fleet{bootstrap: bootstrap, started: started, live: live, current: started}
}

// ApplyConfig implements control.ConfigApplier: whole or not at all.
func (f *Fleet) ApplyConfig(settings map[string]json.RawMessage) ([]string, error) {
	next, err := f.bootstrap.WithFleet(settings)
	if err != nil {
		return nil, err
	}
	if restart := FleetRestartRequired(f.started, next); len(restart) > 0 {
		return restart, nil
	}
	f.mu.Lock()
	f.current = next
	f.mu.Unlock()
	if f.live != nil {
		f.live(next)
	}
	return nil, nil
}

// Current returns the configuration in force now.
func (f *Fleet) Current() *Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.current
}

// --- setting constructors -------------------------------------------------

func fleetDuration(key string, live bool, field func(*Config) *time.Duration) FleetSetting {
	return FleetSetting{
		Key:  key,
		Live: live,
		set: func(c *Config, raw json.RawMessage) error {
			var s string
			if err := strictJSON(raw, &s); err != nil {
				return errors.New(`expected a duration string such as "30s"`)
			}
			d, err := time.ParseDuration(s)
			if err != nil {
				return errors.New(`expected a duration string such as "30s"`)
			}
			*field(c) = d
			return nil
		},
		get: func(c *Config) any { return *field(c) },
	}
}

func fleetInt(key string, live bool, field func(*Config) *int) FleetSetting {
	return FleetSetting{
		Key:  key,
		Live: live,
		set: func(c *Config, raw json.RawMessage) error {
			var n int
			if err := strictJSON(raw, &n); err != nil {
				return errors.New("expected an integer")
			}
			*field(c) = n
			return nil
		},
		get: func(c *Config) any { return *field(c) },
	}
}

func fleetString(key string, live bool, field func(*Config) *string) FleetSetting {
	return FleetSetting{
		Key:  key,
		Live: live,
		set: func(c *Config, raw json.RawMessage) error {
			var s string
			if err := strictJSON(raw, &s); err != nil {
				return errors.New("expected a string")
			}
			*field(c) = s
			return nil
		},
		get: func(c *Config) any { return *field(c) },
	}
}

// strictJSON decodes one JSON value, refusing null and trailing data.
func strictJSON(raw json.RawMessage, dst any) error {
	if len(bytes.TrimSpace(raw)) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return errors.New("null")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data")
	}
	return nil
}
