// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
)

// MethodPerRoute is the name the selector reports. It is not a credential
// method: it is the statement that the method is Hoplock Control's to choose,
// per route (D6a).
const MethodPerRoute = "per-route"

// ErrMethodUnavailable means Hoplock Control chose a method this proxy has no
// local material for — an ephemeral-user route on a proxy with no management
// certificate, a brokered-key route on one with no credential source.
//
// It is separate from ErrUnknownMethod because the two are different jobs: an
// unknown method needs a proxy that implements it, an unavailable one needs
// configuration on this proxy. The user is told the same thing either way
// (PLAN §4.3, outage class); the operator reading the log is not.
var ErrMethodUnavailable = errors.New("auth/target: target authentication method is not configured on this proxy")

// Selector routes each session to the credential method Hoplock Control chose
// for it (D6a, contract v2).
//
// The choice is the server's because one proxy routinely fronts estates that
// need different methods: a Linux fleet that accepts just-in-time provisioning
// and an appliance fleet that can never create a user, behind the same
// listener. `auth.target.method` in config.yaml cannot express that, so it
// stops being the selection and becomes the fallback for a server that names
// none.
//
// What it must never do is fall back to a DIFFERENT method than the one named.
// A route that says ephemeral-user on a proxy with no management certificate
// fails as an outage; serving it with the static key instead would mean
// connecting with credentials the server did not choose, on a host whose audit
// trail then attributes the session to the wrong thing. That is the one
// property this type exists to hold.
type Selector struct {
	methods  map[string]TargetAuthenticator
	fallback string
	logger   *log.Logger
}

var (
	_ TargetAuthenticator = (*Selector)(nil)
	_ Lifecycle           = (*Selector)(nil)
)

// NewSelector returns a selector over the methods this proxy has material for.
// fallback must be one of them: a proxy whose configured method cannot be built
// is misconfigured, and finding that out at the first connection instead of at
// startup helps nobody.
func NewSelector(methods map[string]TargetAuthenticator, fallback string, logger *log.Logger) (*Selector, error) {
	if len(methods) == 0 {
		return nil, errors.New("auth/target: no target authentication method is configured")
	}
	if _, ok := methods[fallback]; !ok {
		return nil, fmt.Errorf("%w: %q is configured as the fallback but has no local material",
			ErrMethodUnavailable, fallback)
	}
	s := &Selector{methods: methods, fallback: fallback, logger: logger}
	s.logf("auth/target: credential methods available: %s (fallback %s, overridden per route by Hoplock Control)",
		strings.Join(s.available(), ", "), fallback)
	return s, nil
}

// Name implements TargetAuthenticator.
func (s *Selector) Name() string { return MethodPerRoute }

// Available lists the configured methods, sorted.
func (s *Selector) available() []string {
	names := make([]string, 0, len(s.methods))
	for name := range s.methods {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Provision dispatches to the method the route named.
func (s *Selector) Provision(ctx context.Context, id *identity.Identity, tgt Target) (*ProvisionedAccess, error) {
	method, err := s.resolve(tgt.Auth)
	if err != nil {
		return nil, err
	}
	return method.Provision(ctx, id, tgt)
}

// resolve picks the authenticator for one route.
func (s *Selector) resolve(auth *control.TargetAuth) (TargetAuthenticator, error) {
	name := s.fallback
	chosen := false
	if auth != nil && auth.Method != "" {
		name = string(auth.Method)
		chosen = true
	}
	method, ok := s.methods[name]
	if ok {
		return method, nil
	}
	if !chosen {
		// Unreachable while NewSelector holds its invariant; kept because the
		// map is a field and a future caller could set it.
		return nil, fmt.Errorf("%w: %q", ErrMethodUnavailable, name)
	}
	if !implemented(name) {
		return nil, fmt.Errorf("%w: %q", ErrUnknownMethod, name)
	}
	return nil, fmt.Errorf("%w: %q", ErrMethodUnavailable, name)
}

// implemented reports whether this build has the named method at all, as
// opposed to having it and lacking the material to run it.
func implemented(name string) bool {
	switch name {
	case MethodEphemeralUser, MethodBrokeredKey, MethodStaticKey:
		return true
	default:
		return false
	}
}

// Start begins any background work the configured methods have (the ephemeral
// method's orphan reaper). It implements Lifecycle.
func (s *Selector) Start(ctx context.Context) {
	for _, method := range s.methods {
		if lc, ok := method.(Lifecycle); ok {
			lc.Start(ctx)
		}
	}
}

// Close ends it.
func (s *Selector) Close() error {
	var errs []error
	for _, method := range s.methods {
		if lc, ok := method.(Lifecycle); ok {
			if err := lc.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (s *Selector) logf(format string, args ...any) {
	if s.logger == nil {
		return
	}
	s.logger.Printf(format, args...)
}
