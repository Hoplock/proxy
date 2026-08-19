// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package identity

import (
	"fmt"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// This file is the single conversion seam between the Control API's wire
// identity (control.Identity) and the proxy's internal model. It lives here, and
// not in internal/control, so the contract package stays a pure description of the
// wire and never depends on the model its consumers use. Every caller that
// crosses the control boundary — user authenticators today, routing and target
// provisioning later — converts through these two functions rather than copying
// fields itself, so a contract change has exactly one place to land.

// FromWire converts an authenticated identity as Hoplock Control returned
// it into the proxy's model, recording how it was proven and when.
//
// It validates, because this is where a contract violation becomes a security
// question: an "authenticated" answer the proxy cannot attribute to a named
// subject must fail the session, not proceed anonymously.
func FromWire(w *control.Identity, method Method, at time.Time) (*Identity, error) {
	if w == nil {
		return nil, fmt.Errorf("%w: Hoplock Control returned no identity", ErrIncomplete)
	}
	id := &Identity{
		Subject:         w.Subject,
		Login:           w.Login,
		DisplayName:     w.DisplayName,
		Source:          w.Source,
		Principals:      cloneStrings(w.Principals),
		Groups:          cloneStrings(w.Groups),
		Claims:          Claims(w.Claims).Clone(),
		Method:          method,
		AuthenticatedAt: at,
	}
	if id.Source == "" {
		id.Source = SourceUnknown
	}
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return id, nil
}

// ToWire converts the identity back into its wire form, for calls that carry an
// already-authenticated identity (Authorize, and the log records that reference
// it). Method and AuthenticatedAt have no wire counterpart on control.Identity;
// AuthorizeRequest.AuthMethod carries the method separately, which WireMethod
// produces.
func (id *Identity) ToWire() *control.Identity {
	if id == nil {
		return nil
	}
	return &control.Identity{
		Subject:     id.Subject,
		Login:       id.Login,
		DisplayName: id.DisplayName,
		Source:      id.Source,
		Principals:  cloneStrings(id.Principals),
		Groups:      cloneStrings(id.Groups),
		Claims:      map[string]string(id.Claims.Clone()),
	}
}

// WireMethod returns the contract's name for this authentication method, for
// AuthorizeRequest.AuthMethod. The two enums are kept as separate types on
// purpose: the internal model must be able to gain a method (an OIDC flow, say)
// before the contract does, and vice versa.
func (m Method) WireMethod() control.AuthMethod {
	switch m {
	case MethodCert:
		return control.AuthMethodCert
	case MethodPasswordMFA:
		return control.AuthMethodPasswordMFA
	default:
		return ""
	}
}
