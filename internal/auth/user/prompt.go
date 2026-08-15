// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package user

import (
	"context"
	"fmt"
	"time"
)

// MFAPrompter is how an authenticator speaks to the user while an out-of-band
// second factor is outstanding (PLAN §4.3). The SSH layer implements it over
// keyboard-interactive; tests implement it to assert what the user was told.
//
// It exists because a bastion that waits silently for a phone approval is
// indistinguishable from a bastion that has hung. Everything here is
// informational: a prompter never collects an answer, it only speaks.
type MFAPrompter interface {
	// Challenge is called once, when the management server issues the
	// challenge, with the server's own prompt text.
	Challenge(instruction string) error
	// Waiting is called while polling, with how long the user has been waiting,
	// so a slow approval shows progress instead of silence.
	Waiting(instruction string, elapsed time.Duration) error
}

// prompterKey is the context key carrying the prompter.
type prompterKey struct{}

// WithMFAPrompter attaches p to ctx.
//
// The prompter travels in the context rather than in ConnMeta or the method
// signature because UserAuthenticator is fixed by PLAN §4.1 and takes only
// (ctx, meta, credential): meta is connection *data* that is converted to the
// wire, while the prompter is a live callback into the SSH layer that exists
// only for the duration of one keyboard-interactive callback. Tying its
// lifetime to the context is what keeps it from outliving that callback.
func WithMFAPrompter(ctx context.Context, p MFAPrompter) context.Context {
	if p == nil {
		return ctx
	}
	return context.WithValue(ctx, prompterKey{}, p)
}

// prompterFrom returns the prompter attached to ctx, or one that says nothing.
// A missing prompter is normal — a certificate login has no one to talk to, and
// so does a test — so it is never an error.
func prompterFrom(ctx context.Context) MFAPrompter {
	if p, ok := ctx.Value(prompterKey{}).(MFAPrompter); ok && p != nil {
		return p
	}
	return silentPrompter{}
}

// silentPrompter discards everything.
type silentPrompter struct{}

func (silentPrompter) Challenge(string) error              { return nil }
func (silentPrompter) Waiting(string, time.Duration) error { return nil }

// DefaultMFAPrompt is shown when the management server issues a challenge with
// no prompt text of its own. The server's text is preferred: it knows which
// factor the user actually has.
const DefaultMFAPrompt = "Approve the login request on your second factor to continue."

// waitingText is the "still waiting" line sent between polls. It repeats the
// original instruction so a user who missed the first message still learns what
// is being asked of them, and it counts up so the session visibly progresses.
func waitingText(instruction string, elapsed time.Duration) string {
	return fmt.Sprintf("Still waiting for approval (%ds)... %s",
		int(elapsed.Round(time.Second)/time.Second), instruction)
}
