// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// Parameter names defined by the contract (api/README.md, "Target
// credentials"). They are scoped to their method: `username` means the account
// to create for ephemeral-user and the account that already exists for
// brokered-key, which is why each method parses its own.
const (
	// ParamUsername names the account on the target.
	ParamUsername = "username"
	// ParamKeyType selects the ephemeral key algorithm.
	ParamKeyType = "key_type"
	// ParamLifetimeSeconds bounds how long the ephemeral key stays valid.
	ParamLifetimeSeconds = "lifetime_seconds"
	// ParamCredentialRef selects which local material a brokered-key session
	// uses. It is an opaque handle, never credential material (D6a).
	ParamCredentialRef = "credential_ref"
)

// ErrUnknownParam means the route carried a parameter this proxy does not
// implement.
//
// Refusing is the contract's rule and not pedantry: `params` is open so that
// methods can grow, and an unknown parameter may be a CONSTRAINT — a lifetime,
// an allowed source address, a required certificate extension. Ignoring one
// means connecting on terms the server did not agree to, which is the same
// failure as picking a method it did not choose.
var ErrUnknownParam = errors.New("auth/target: unknown target_auth parameter")

// ErrInvalidParam means a parameter this proxy implements had an unusable
// value.
var ErrInvalidParam = errors.New("auth/target: invalid target_auth parameter")

// params is one route's target_auth parameter map, consumed key by key so that
// whatever is left over can be refused.
type params struct {
	values map[string]string
	used   map[string]bool
}

func newParams(auth *control.TargetAuth) *params {
	p := &params{values: map[string]string{}, used: map[string]bool{}}
	if auth != nil {
		for k, v := range auth.Params {
			p.values[k] = v
		}
	}
	return p
}

// str consumes a string parameter, returning fallback when it is absent.
func (p *params) str(name, fallback string) string {
	p.used[name] = true
	if v, ok := p.values[name]; ok && v != "" {
		return v
	}
	return fallback
}

// duration consumes a parameter expressed in whole seconds.
func (p *params) duration(name string) (time.Duration, bool, error) {
	p.used[name] = true
	v, ok := p.values[name]
	if !ok || v == "" {
		return 0, false, nil
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs <= 0 {
		// The value is echoed because a parameter is policy metadata, not
		// credential material; no method defines a secret-valued parameter and
		// the contract forbids one (D6a).
		return 0, false, fmt.Errorf("%w: %s=%q must be a positive whole number of seconds", ErrInvalidParam, name, v)
	}
	return time.Duration(secs) * time.Second, true, nil
}

// rest reports any parameter the method did not consume.
func (p *params) rest() error {
	var unknown []string
	for name := range p.values {
		if !p.used[name] {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("%w: %v", ErrUnknownParam, unknown)
}
