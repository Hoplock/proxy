// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"encoding/json"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// This file is where D16's grant context becomes record attributes and stops
// being anything else (contract v4, PLAN §6.5, §13 UC3). The grant context is
// WHY an external system says access was granted; the proxy copies it onto
// every record the session produces, never parses it, never matches against it,
// never decides anything from it (D2, D15), and never shows it to the user.
//
// Phase 0018 made that structural rather than a comment: an AST walk
// (TestGrantContextIsNotConsultedByAnyDecisionPath) says internal/control
// defines the type, cmd/mock-control authors it, and THIS package is the only
// one that may read it. Carrying the value from the authorize response to the
// recorder must therefore not add a fourth package to that list — which is why
// the extraction happens here, from the response itself, rather than in the
// routing layer that holds the response first. internal/routing and
// internal/proxy carry a *Grant between them, and a *Grant is a handle with no
// exported field and no exported method: the only thing either package can do
// with it is hand it back.

// Grant is one session's grant context in carriable form.
//
// It is deliberately inert. Its single field is the attributes a record will
// carry, computed once at construction, so "the proxy decided something from
// the grant context" is not a rule anybody has to remember — there is nothing
// on the type to decide from. That is the same reasoning control.GrantContext
// carries no Matches method, enforced one layer out.
type Grant struct{ attrs Attrs }

// GrantFrom keeps what a record needs of an authorize response's grant context,
// and returns nil when there is nothing to carry.
//
// It takes the whole response rather than the grant context itself for the
// reason at the top of this file: the parameter type is what keeps every other
// package's source free of the identifier, and a nil response or an absent
// grant context is the ordinary case (a route with no external grant, which is
// every route a v3 server answered).
func GrantFrom(resp *control.AuthorizeResponse) *Grant {
	if resp == nil || resp.GrantContext == nil {
		return nil
	}
	g := resp.GrantContext
	attrs := Attrs{}.
		Set(AttrGrantSystem, g.System).
		Set(AttrGrantReference, g.Reference)
	if g.WindowStart != nil {
		attrs.Set(AttrGrantWindowStart, g.WindowStart.UTC().Format(time.RFC3339))
	}
	if g.WindowEnd != nil {
		attrs.Set(AttrGrantWindowEnd, g.WindowEnd.UTC().Format(time.RFC3339))
	}
	if a := g.Additional; a != nil {
		// The two forms additional_context takes are kept as the two different
		// things they are. A string is one attribute; an OBJECT becomes one
		// attribute per field, which is the AttrDeviceFieldPrefix pattern and
		// for the same reason: an auditor asks "which sessions did change
		// CHG-1234 authorise", and a whole object flattened into one string
		// turns that question into a substring search. Stringifying the object
		// form would also put words in the asserting system's mouth, which is
		// what control.AdditionalContext refuses to do on the way in.
		switch {
		case a.Fields != nil:
			for name, value := range a.Fields {
				attrs.Set(AttrGrantAdditionalPrefix+name, additionalValue(value))
			}
		default:
			attrs.Set(AttrGrantAdditional, a.Text)
		}
	}
	if len(attrs) == 0 {
		return nil
	}
	return &Grant{attrs: attrs}
}

// additionalValue renders one field of the object form.
//
// A string is carried exactly as it arrived — which is every field a
// ticket-shaped integration sends. Anything else is re-encoded as the JSON it
// came as, because the alternative is Go's own rendering of a decoded value
// (1e+06 for a million) in a record an auditor reads as the external system's
// words.
func additionalValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		// Unreachable for anything that arrived as JSON. Losing one field is
		// better than losing the record it belongs to, which is the rule every
		// lenient reader in this package follows.
		return ""
	}
	return string(encoded)
}

// stamp copies the grant context onto a record's attributes.
//
// Every key is in the grant's own namespace (AttrGrant*), so it can collide
// with nothing a capture point sets and the order the two are written in does
// not matter.
func (g *Grant) stamp(attrs Attrs) Attrs {
	if g == nil {
		return attrs
	}
	for key, value := range g.attrs {
		attrs.Set(key, value)
	}
	return attrs
}
