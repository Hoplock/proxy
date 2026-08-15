// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package user

import (
	"errors"
	"fmt"

	"github.com/mauroasilva/securecommandproxy/internal/mgmt"
)

// This file owns what the person at the SSH prompt is told when authentication
// fails (PLAN §4.3). The rule has exactly two branches and they must never be
// collapsed into one message:
//
//   - A deny is deliberately vague. It names neither the login nor the target,
//     and does not say which of the two was the problem, because a precise
//     denial turns the bastion into an oracle for probing the estate: "user
//     unknown" versus "no access to that host" is a directory listing given away
//     one login attempt at a time.
//   - Everything else is explicit and honest. The bastion could not reach a
//     decision, that is an outage rather than a permissions problem, and saying
//     so is what stops a user from re-typing their password forever or filing a
//     ticket against the wrong team. It carries the session id, which is safe to
//     disclose and is what turns a mystery disconnect into a ticket the logs can
//     answer.
//
// Both outcomes still refuse the connection. The distinction is in disclosure,
// never in whether access was granted.

// DenyMessage is shown for every deny decision, whatever was actually wrong.
const DenyMessage = "Access denied."

// BannerMessage is sent before authentication so the user knows the pause is
// the bastion consulting the policy service rather than a stalled connection
// (PLAN §4.3, the SSH_MSG_USERAUTH_BANNER row).
func BannerMessage(sessionID string) string {
	if sessionID == "" {
		return "SecureCommandProxy: checking your access with the policy service.\r\n"
	}
	return fmt.Sprintf("SecureCommandProxy: checking your access with the policy service. Session %s.\r\n", sessionID)
}

// OutageMessage is shown when no decision could be obtained. It states plainly
// that this is not a permissions problem, so the user does not retry a denial
// that was never a denial, and quotes the session id as the support reference.
func OutageMessage(sessionID string) string {
	msg := "The bastion could not reach a decision because the policy service is unavailable. " +
		"This is a service problem, not a permissions problem — retrying with different credentials will not help."
	if sessionID != "" {
		msg += fmt.Sprintf(" Quote session id %s when reporting this.", sessionID)
	}
	return msg
}

// FailureMessage renders the message for an authentication failure, applying
// the split above. It is exported because the same rule governs the failures
// the proxy reports after authentication (0005): one implementation of the rule,
// used everywhere, is what keeps the two branches from converging by accident.
//
// A nil error is treated as an outage rather than a success: a caller that
// reached a failure path without an error has a bug, and the safe rendering of
// "I do not know why this failed" is never "you are not allowed".
func FailureMessage(err error, sessionID string) string {
	if IsDenied(err) {
		return DenyMessage
	}
	return OutageMessage(sessionID)
}

// IsDenied reports whether err is a deny decision — the only classification
// that may be shown to a user as a permissions problem.
//
// It accepts a raw management client error as well as this package's sentinels,
// so a caller cannot get the disclosure wrong by forgetting to translate first.
func IsDenied(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrUnavailable) {
		return false
	}
	return errors.Is(err, ErrDenied) || mgmt.IsUnauthorized(err)
}
