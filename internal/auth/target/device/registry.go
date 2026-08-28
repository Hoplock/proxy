// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package device

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ErrUnknownPlatform means the route named a platform this proxy has no driver
// for.
//
// It is an OUTAGE-CLASS DENIAL (PLAN §4.3) and NEVER A GUESS. The proxy does
// not sniff a banner, does not fall back to a driver for a platform that "looks
// similar", and does not try the commands anyway: guessing wrong means running
// configuration commands against the wrong parser, on a device whose
// configuration is the customer's production network. The contract already
// refuses a platform value that is not a platform NAME (control.Validate); this
// is the separate question of whether a driver for a well-formed name exists,
// and it is separate because D13 makes customer-written drivers a first-class
// case — the set of platforms is open, so the contract cannot enumerate it.
var ErrUnknownPlatform = errors.New("auth/target/device: no driver for this platform")

// ErrDuplicatePlatform means two drivers claimed the same platform name.
//
// It is refused at registration rather than resolved by order, because which of
// two drivers a route gets would then depend on link order — and the loser
// would be a driver somebody installed on purpose.
var ErrDuplicatePlatform = errors.New("auth/target/device: platform already has a driver")

// Registry maps the contract's `platform` parameter (control.ParamPlatform) to
// the driver that implements it.
//
// There is one of these per proxy, built at startup. It is safe for concurrent
// use: the reaper enumerates platforms on its own schedule while sessions look
// them up.
type Registry struct {
	mu      sync.RWMutex
	drivers map[string]Driver
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{drivers: make(map[string]Driver)}
}

// Register adds a driver under its own Platform name.
func (r *Registry) Register(d Driver) error {
	if d == nil {
		return errors.New("auth/target/device: cannot register a nil driver")
	}
	platform := d.Platform()
	if platform == "" {
		return errors.New("auth/target/device: cannot register a driver with no platform name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.drivers[platform]; ok {
		return fmt.Errorf("%w: %q", ErrDuplicatePlatform, platform)
	}
	r.drivers[platform] = d
	return nil
}

// Lookup returns the driver for a platform, or ErrUnknownPlatform.
func (r *Registry) Lookup(platform string) (Driver, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPlatform, platform)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.drivers[platform]
	if !ok {
		// The known platforms are named so an operator sees at once whether
		// this is a typo in policy or a driver this build does not carry.
		return nil, fmt.Errorf("%w: %q (this proxy has: %v)", ErrUnknownPlatform, platform, r.platformsLocked())
	}
	return d, nil
}

// Platforms lists the registered platform names, sorted. It is what a proxy
// advertises to Hoplock Control, so that Control never names a platform the
// proxy has no driver for.
func (r *Registry) Platforms() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.platformsLocked()
}

func (r *Registry) platformsLocked() []string {
	names := make([]string, 0, len(r.drivers))
	for name := range r.drivers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Drivers returns the registered drivers, ordered by platform name.
func (r *Registry) Drivers() []Driver {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Driver, 0, len(r.drivers))
	for _, name := range r.platformsLocked() {
		out = append(out, r.drivers[name])
	}
	return out
}

// shipped holds the drivers THIS REPOSITORY ships. It is empty in phase 0013 —
// the seam lands before the first driver, deliberately — and phase 0014
// registers the FortiOS drivers into it.
var shipped = NewRegistry()

// Shipped returns the registry of drivers this repository ships.
//
// It is separate from a registry an operator builds because the invariant below
// is scoped to Hoplock's own drivers: a customer driver may persist accounts,
// and a registry holding one must not be rejected for it.
func Shipped() *Registry { return shipped }

// CheckShipped reports whether every driver in a registry meets the rules a
// HOPLOCK-SHIPPED driver must meet.
//
// Today there is one rule and it is D13's, as phase 0014 amended it: a Hoplock
// driver may declare PersistsAcrossReload only when the platform leaves it no
// choice, and must say which platform mechanism forces it. What is forbidden is
// the SILENT declaration — persistence as a convenience, with nothing to review.
//
// It is expressed as a check over the registry rather than as a comment on the
// field because a comment is not something a build can fail, and this is
// exactly the kind of declaration that gets flipped to true in the course of
// making one stubborn platform work. The amendment does not weaken that: it
// moves the bar from "must be false" to "must be justified in writing", which
// is a bar a passing-by change still cannot clear by accident.
func CheckShipped(r *Registry) error {
	for _, d := range r.Drivers() {
		caps := d.Capabilities()
		if caps.PersistsAcrossReload && strings.TrimSpace(caps.PersistenceReason) == "" {
			return fmt.Errorf(
				"auth/target/device: shipped driver %q declares PersistsAcrossReload with no "+
					"PersistenceReason, which a Hoplock driver may not (D13): persisting the "+
					"account to saved configuration means a crashed proxy leaves a standing "+
					"administrator that no reload clears, which demotes the product's claim "+
					"from \"no standing accounts\" to \"no standing accounts while the proxy "+
					"is healthy\". Phase 0014 relaxed the original outright ban because "+
					"FortiOS leaves a driver no choice, but only that far: a shipped driver "+
					"that persists must name the PLATFORM mechanism that forces it, so the "+
					"claim can be checked rather than taken on trust, and so the provisioner "+
					"can record it on every session it serves. A driver that persists BY "+
					"CHOICE still may not ship. A CUSTOMER driver is not bound by this at all",
				d.Platform())
		}
	}
	return nil
}
