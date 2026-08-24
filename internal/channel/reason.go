// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package channel

import "github.com/hoplock/proxy/internal/control"

// This file holds every clause the pipeline hands back for a denial.
//
// They are clauses, not messages: internal/proxy renders each one behind the
// generic denial from PLAN §4.3, so the deny/outage split keeps exactly one
// implementation. What belongs here is the other half of that rule — saying
// enough that a user knows they were refused and what was refused, while
// disclosing nothing they had not already said themselves. Every clause below
// names only the thing the client asked for, so none of them can be used to
// map a policy the client cannot already see.

// channelTypeReason is the clause for a channel type the session may not open.
func channelTypeReason(channelType string) string {
	return "Channel type " + channelType + " is not available on this session."
}

// forwardReason is the clause for a forwarding destination outside the route's
// list. It repeats the destination the client asked for, which reveals nothing:
// the client chose it.
func forwardReason(f Forward) string {
	return "Forwarding to " + f.String() + " is not available on this session."
}

// malformedForwardReason is the clause for a forwarding payload the proxy could
// not read. It is deliberately not an outage: an unreadable destination is one
// the policy cannot be applied to, and the answer to that is no.
const malformedForwardReason = "The forwarding request could not be read."

// malformedRequestReason is the same for an in-channel request payload.
const malformedRequestReason = "The request could not be read."

// requestReason is the clause for an in-channel request the session may not
// make. Each of the requests that decides what a session channel *is* gets its
// own wording, because "request pty-req was refused" is a protocol detail and
// "you do not get a terminal here" is what the user needs in order to stop
// retrying (PLAN §4.3).
func requestReason(requestType string) string {
	switch requestType {
	case control.RequestPTY:
		return "An interactive terminal is not available on this session."
	case control.RequestShell:
		return "An interactive shell is not available on this session."
	case control.RequestExec:
		return "Running commands is not available on this session."
	case control.RequestEnv:
		return "Setting environment variables is not available on this session."
	case control.RequestX11:
		return "X11 forwarding is not available on this session."
	case control.RequestAuthAgent:
		return "Agent forwarding is not available on this session."
	default:
		return "Request " + requestType + " is not available on this session."
	}
}

// subsystemReason is the clause for a subsystem the session may not start. It
// names the subsystem because the client named it first, and because "sftp is
// not available here" is the difference between a user who files a ticket and
// one who assumes the proxy is broken.
func subsystemReason(name string) string {
	if name == "" {
		return "That subsystem is not available on this session."
	}
	return "The " + name + " subsystem is not available on this session."
}
