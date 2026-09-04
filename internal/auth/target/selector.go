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

// RungChecker is implemented by a method that can tell, WITHOUT CONNECTING,
// whether it can satisfy one ladder rung (D14).
//
// It has to be answerable without connecting because a rung the selector is
// about to SKIP has nothing to connect to: asking "can you serve this?" by
// dialling a firewall would make walking past an entry cost a round trip to the
// device the entry names. A method that does not implement it is satisfiable
// whenever this proxy has material for it, which is the pre-ladder behaviour.
type RungChecker interface {
	// CanSatisfy returns nil when the rung is servable, an error wrapping
	// ErrRungUnsatisfiable when it is not, and any other error for a rung this
	// proxy cannot even read.
	CanSatisfy(auth *control.TargetAuth, tgt Target) error
}

// ErrLadderExhausted means the server's ladder ran out before this proxy found
// an entry it could satisfy.
//
// It is a CLEAN DENIAL, and it is the reason the ladder is safe: the proxy
// never connects with a method the server did not name (D6a's surviving rule),
// so running out of named methods is the end of the road rather than an
// invitation to improvise.
var ErrLadderExhausted = errors.New("auth/target: none of the credential methods the server named can be satisfied by this proxy")

// Provision walks the route's credential ladder and serves the first entry this
// proxy can satisfy (D14).
//
// The walk is the whole of D14 and its shape is the argument for it. D6a said
// an unsatisfiable method is a clean denial and never a silent fallback; the
// rule was right and its conclusion was too narrow, because a session that does
// not happen produces no recording, no command policy, and no audit trail. What
// made fallback unacceptable was never degradation — it was the PROXY choosing.
// So the list is the server's, the order is the server's, and this function
// only ever moves DOWN it.
//
// Two things it must never do, and the difference between them is exactly the
// distinction phase 0013 built into the driver errors:
//
//   - It never skips a rung because an ATTEMPT failed. A device that is
//     unreachable, a command the device refused, a credential that would not
//     install — each of those fails the session, because dropping to a weaker
//     rung the server ranked lower on a transient failure is how an outage
//     becomes a downgrade.
//   - It never invents a rung. An exhausted ladder is a denial.
func (s *Selector) Provision(ctx context.Context, id *identity.Identity, tgt Target) (*ProvisionedAccess, error) {
	rungs, named := s.rungs(tgt)
	if !named {
		method, err := s.resolve(nil)
		if err != nil {
			return nil, err
		}
		return s.provisionOne(ctx, id, tgt, method, nil, 0)
	}
	if len(rungs) == 0 {
		// An empty ladder is a denial the server wrote, not an absence.
		return nil, fmt.Errorf("%w: the server named an empty ladder", ErrLadderExhausted)
	}

	var skipped []error
	for i := range rungs {
		rung := rungs[i]
		method, err := s.resolve(&rung)
		if err != nil {
			skipped = append(skipped, rungErr(i+1, rung, err))
			continue
		}
		if checker, ok := method.(RungChecker); ok {
			if err := checker.CanSatisfy(&rung, tgt); err != nil {
				if !errors.Is(err, ErrRungUnsatisfiable) {
					// A rung this proxy cannot READ is different from one it
					// cannot satisfy: the server hid a constraint in it, and
					// walking past it would serve the route on terms nobody
					// agreed to (the same rule params.rest enforces).
					return nil, err
				}
				skipped = append(skipped, rungErr(i+1, rung, err))
				continue
			}
		}
		return s.provisionOne(ctx, id, tgt, method, &rung, i+1)
	}
	return nil, &ladderError{causes: skipped}
}

// rungErr labels why one entry was passed over.
func rungErr(index int, rung control.TargetAuth, err error) error {
	return fmt.Errorf("[%d] %s: %w", index, rung.Method, err)
}

// ladderError is an exhausted ladder that still answers for every entry.
//
// It wraps ErrLadderExhausted AND each rung's own cause, which matters because
// a one-entry ladder is D6a's original behaviour exactly: a route naming a
// method this proxy has no material for must still be ErrMethodUnavailable to
// anything asking, and one naming a method this build lacks must still be
// ErrUnknownMethod. The ladder is a new shape around those answers, not a new
// answer.
type ladderError struct{ causes []error }

func (e *ladderError) Error() string {
	parts := make([]string, 0, len(e.causes))
	for _, c := range e.causes {
		parts = append(parts, c.Error())
	}
	return fmt.Sprintf("%s: %s", ErrLadderExhausted, strings.Join(parts, "; "))
}

// Unwrap returns every cause, so errors.Is finds the sentinel and the reasons
// alike.
func (e *ladderError) Unwrap() []error {
	return append([]error{ErrLadderExhausted}, e.causes...)
}

// provisionOne runs one rung and labels what it produced.
func (s *Selector) provisionOne(ctx context.Context, id *identity.Identity, tgt Target, method TargetAuthenticator, rung *control.TargetAuth, index int) (*ProvisionedAccess, error) {
	tgt.Auth = rung
	tgt.Rung = index
	// An APPLIED target rung on a method that touches nothing is refused BEFORE
	// the method runs, so the session is denied with the target exactly as it
	// was found. The contract's own Validate refuses that combination for a
	// named ladder (0018), which is why reaching it here means a locally
	// configured route rather than a served one — and it is still refused,
	// because serving it would put a rung on the audit record that nothing
	// applied.
	if !control.TargetAuthMethod(method.Name()).Provisions() {
		if _, err := resultForUnprovisioned(tgt.Enforcement, method.Name()); err != nil {
			return nil, err
		}
	}
	access, err := method.Provision(ctx, id, tgt)
	if err != nil {
		return nil, err
	}
	if access != nil {
		// A method that labelled its own result keeps its label; anything else
		// is labelled here, so the audit record always names the entry that was
		// used rather than only sometimes (D14).
		if access.Method == "" {
			access.Method = method.Name()
		}
		if access.Rung == 0 {
			access.Rung = index
		}
		if access.Enforcement == nil {
			// A method that rendered nothing still owes the record an answer.
			// The two proxy-side rungs and an ATTESTED rung are all satisfiable
			// without touching the target, and the attested one is the point of
			// having the distinction: the appliance enforces its own roles
			// already, and the record must say `platform-attested` rather than
			// "none" (0018).
			result, err := resultForUnprovisioned(tgt.Enforcement, access.Method)
			if err != nil {
				_ = access.Close(ctx)
				return nil, err
			}
			access.Enforcement = result
		}
	}
	if index > 1 {
		// The rung in force goes to the record and the operator surface, never
		// to the user (D14): the information is about the estate rather than
		// about the user's own request.
		s.logf("auth/target: session used ladder entry %d (%s) — earlier entries could not be satisfied", index, access.Method)
	}
	return access, nil
}

// rungs reads the route's ladder, preserving the absent/empty distinction.
func (s *Selector) rungs(tgt Target) (rungs []control.TargetAuth, named bool) {
	if tgt.Ladder != nil {
		return []control.TargetAuth(*tgt.Ladder), true
	}
	if tgt.Auth != nil {
		// A v2 single object is a one-entry ladder, which is D6a's original
		// behaviour exactly (phase 0013's AuthorizeResponse.Ladder says the
		// same thing on the wire side).
		return []control.TargetAuth{*tgt.Auth}, true
	}
	return nil, false
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
	case MethodEphemeralUser, MethodEphemeralAccount, MethodBrokeredKey, MethodStaticKey:
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
