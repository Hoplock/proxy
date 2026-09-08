// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package routing

import "time"

// This file holds the one rule a session deadline has that is about ROUTING
// rather than about the timer: along a chain it may only ever shorten
// (D11, D16). Everything else the deadline does is internal/proxy's —
// see internal/proxy/deadline.go.

// ShortenDeadline returns the earlier of two session deadlines, treating nil as
// "no opinion". It is resolveMaxHops' sibling and follows the same rule for the
// same reason: on a chain the strictest bound wins, and a hop may narrow what
// it was told, never widen it (D2).
//
// The case it exists for is a hop whose own authorize call answers with a LATER
// deadline than the session arrived carrying. That answer is not wrong — each
// hop authorizes independently, and Hoplock Control may legitimately give this
// leg a different one — but taking it would extend a session past the bound the
// first hop was given. Since the deadline travels as an absolute instant, the
// comparison is meaningful across hops; a duration would have re-anchored at
// every one of them, multiplying the window silently, which is why 0018 chose
// the instant.
func ShortenDeadline(inherited, own *time.Time) *time.Time {
	switch {
	case inherited == nil:
		return cloneInstant(own)
	case own == nil:
		return cloneInstant(inherited)
	case own.Before(*inherited):
		return cloneInstant(own)
	default:
		return cloneInstant(inherited)
	}
}

// cloneInstant copies an optional instant out of a value that may be shared.
// A cached authorize decision is handed to more than one session (PLAN §6.4),
// so nothing derived from one may alias it.
func cloneInstant(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	at := *t
	return &at
}

// formatDeadline renders an optional deadline for a log line, saying "none"
// rather than printing a zero instant: absent is not zero, and a log that
// spelled it "0001-01-01T00:00:00Z" would read as a session already over.
func formatDeadline(t *time.Time) string {
	if t == nil {
		return "none"
	}
	return t.UTC().Format(time.RFC3339)
}
