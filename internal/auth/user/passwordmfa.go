// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package user

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mauroasilva/securecommandproxy/internal/identity"
	"github.com/mauroasilva/securecommandproxy/internal/mgmt"
)

// MethodPasswordMFA is the registry/config name of the password+MFA
// authenticator, derived from identity.MethodPasswordMFA so config, logs, and
// the authenticated identity always agree on the name.
const MethodPasswordMFA = string(identity.MethodPasswordMFA)

// MFA polling defaults.
const (
	// DefaultMinPollInterval floors the server's poll_after_ms so a
	// misconfigured or hostile challenge cannot turn the bastion into a polling
	// hot loop against the management server.
	DefaultMinPollInterval = 500 * time.Millisecond
	// DefaultProgressInterval is how often the user is told the bastion is
	// still waiting. It is decoupled from the poll interval on purpose: polling
	// fast and talking fast are different concerns, and a line per poll would
	// scroll the real instruction off the screen.
	DefaultProgressInterval = 5 * time.Second
	// DefaultMaxWait caps the whole out-of-band wait when the challenge carries
	// no usable expiry. The server's ExpiresAt wins whenever it is set and
	// sooner — the bastion may give up earlier than the server, never later.
	DefaultMaxWait = 2 * time.Minute
)

// PasswordMFAOptions tunes the out-of-band wait.
type PasswordMFAOptions struct {
	// MinPollInterval floors MFAChallenge.PollAfter(). Zero means
	// DefaultMinPollInterval.
	MinPollInterval time.Duration
	// ProgressInterval is the minimum gap between "still waiting" messages.
	// Zero means DefaultProgressInterval; negative disables them.
	ProgressInterval time.Duration
	// MaxWait caps the total wait. Zero means DefaultMaxWait.
	MaxWait time.Duration
}

func (o PasswordMFAOptions) withDefaults() PasswordMFAOptions {
	if o.MinPollInterval <= 0 {
		o.MinPollInterval = DefaultMinPollInterval
	}
	if o.ProgressInterval == 0 {
		o.ProgressInterval = DefaultProgressInterval
	}
	if o.MaxWait <= 0 {
		o.MaxWait = DefaultMaxWait
	}
	return o
}

// PasswordMFAAuthenticator authenticates a client by password plus an
// out-of-band second factor, and is the fallback for clients with no acceptable
// certificate (PLAN §4.1).
//
// The password is relayed to the management server and never stored, logged, or
// wrapped into an error by anything in this type (PLAN §7). The only place it
// appears is the request struct, which redacts itself when formatted.
//
// The MFA wait lives here rather than in the SSH layer because it is a property
// of the decision, not of the transport: the server states the poll interval
// and the expiry, and the bastion obeys both.
type PasswordMFAAuthenticator struct {
	opts Options
	mfa  PasswordMFAOptions
}

var (
	_ UserAuthenticator = (*PasswordMFAAuthenticator)(nil)
	_ FlowSupport       = (*PasswordMFAAuthenticator)(nil)
)

// NewPasswordMFAAuthenticator returns a password+MFA authenticator.
func NewPasswordMFAAuthenticator(opts Options, mfaOpts PasswordMFAOptions) (*PasswordMFAAuthenticator, error) {
	if opts.Client == nil {
		return nil, errors.New("auth/user: password-mfa authenticator requires a management client")
	}
	return &PasswordMFAAuthenticator{opts: opts, mfa: mfaOpts.withDefaults()}, nil
}

// Name implements UserAuthenticator.
func (a *PasswordMFAAuthenticator) Name() string { return MethodPasswordMFA }

// SupportsCert implements FlowSupport.
func (a *PasswordMFAAuthenticator) SupportsCert() bool { return false }

// SupportsPassword implements FlowSupport.
func (a *PasswordMFAAuthenticator) SupportsPassword() bool { return true }

// AuthenticateCert implements UserAuthenticator. This authenticator has no
// certificate flow.
func (a *PasswordMFAAuthenticator) AuthenticateCert(context.Context, ConnMeta, ssh.PublicKey) (*identity.Identity, error) {
	return nil, fmt.Errorf("%s: %w", MethodPasswordMFA, ErrMethodNotSupported)
}

// AuthenticatePassword implements UserAuthenticator. It relays the password and,
// when the server asks for a second factor, waits for it while keeping the user
// informed through the context's MFAPrompter.
func (a *PasswordMFAAuthenticator) AuthenticatePassword(ctx context.Context, meta ConnMeta, password string) (*identity.Identity, error) {
	const op = "password-mfa"

	now := a.opts.now()
	req := &mgmt.AuthenticatePasswordRequest{
		Login:    meta.Login,
		Target:   meta.Target,
		Password: password,
		Conn:     meta.wire(now),
	}

	a.opts.logf("auth: session=%s method=%s login=%q: asking management server",
		meta.SessionID, MethodPasswordMFA, meta.Login)

	resp, err := a.opts.Client.AuthenticatePassword(ctx, req)
	if err != nil {
		outcome := classify(op, err)
		a.opts.logf("auth: session=%s method=%s login=%q: %v",
			meta.SessionID, MethodPasswordMFA, meta.Login, outcome)
		return nil, outcome
	}

	switch resp.Status {
	case mgmt.AuthStatusAuthenticated:
		return a.accept(op, meta, resp.Identity, now)
	case mgmt.AuthStatusMFARequired:
		return a.awaitMFA(ctx, op, meta, resp.MFA)
	default:
		// Unreachable through RESTClient, which rejects unknown statuses, but a
		// Client is an interface: an unknown status is "no decision", not a deny.
		outcome := fmt.Errorf("%s: %w: unexpected status %q", op, ErrUnavailable, resp.Status)
		a.opts.logf("auth: session=%s method=%s login=%q: %v",
			meta.SessionID, MethodPasswordMFA, meta.Login, outcome)
		return nil, outcome
	}
}

// accept converts a successful response and logs the outcome.
func (a *PasswordMFAAuthenticator) accept(op string, meta ConnMeta, w *mgmt.Identity, at time.Time) (*identity.Identity, error) {
	id, err := identityFrom(op, w, identity.MethodPasswordMFA, at)
	if err != nil {
		a.opts.logf("auth: session=%s method=%s login=%q: %v",
			meta.SessionID, MethodPasswordMFA, meta.Login, err)
		return nil, err
	}
	a.opts.logf("auth: session=%s method=%s login=%q: authenticated subject=%s source=%s",
		meta.SessionID, MethodPasswordMFA, meta.Login, id.Subject, id.Source)
	return id, nil
}

// awaitMFA polls the outstanding challenge until it resolves, expires, or the
// context ends, telling the user what is happening throughout.
//
// Three bounds apply at once and the earliest wins: the challenge's ExpiresAt,
// the configured MaxWait, and the caller's context. The bastion never polls
// past the expiry the server set — a token is single-use and dead after it, so
// polling on would only turn a deny into a slower deny.
func (a *PasswordMFAAuthenticator) awaitMFA(ctx context.Context, op string, meta ConnMeta, challenge *mgmt.MFAChallenge) (*identity.Identity, error) {
	// The client guarantees an mfa_required response carries a challenge with a
	// token; guard anyway, because Client is an interface.
	if challenge == nil || challenge.Token == "" {
		return nil, fmt.Errorf("%s: %w: management server requested MFA without a challenge", op, ErrUnavailable)
	}

	prompter := prompterFrom(ctx)
	instruction := challenge.Prompt
	if instruction == "" {
		instruction = DefaultMFAPrompt
	}

	start := a.opts.now()
	deadline := start.Add(a.mfa.MaxWait)
	if !challenge.ExpiresAt.IsZero() && challenge.ExpiresAt.Before(deadline) {
		deadline = challenge.ExpiresAt
	}

	a.opts.logf("auth: session=%s method=%s login=%q: awaiting out-of-band approval until %s",
		meta.SessionID, MethodPasswordMFA, meta.Login, deadline.UTC().Format(time.RFC3339))

	if err := prompter.Challenge(instruction); err != nil {
		// The user's client hung up or refused the info request; there is
		// nobody left to approve. This is not a server decision.
		return nil, fmt.Errorf("%s: %w: %w", op, ErrUnavailable, err)
	}

	interval := a.pollInterval(challenge)
	lastProgress := start

	for {
		if err := sleep(ctx, interval); err != nil {
			return nil, fmt.Errorf("%s: %w: %w", op, ErrUnavailable, err)
		}

		now := a.opts.now()
		if !now.Before(deadline) {
			// An unapproved challenge is a failed authentication, and it is
			// reported as a deny: the user is told only "access denied", which
			// is the same thing a wrong password is told (PLAN §4.3).
			a.opts.logf("auth: session=%s method=%s login=%q: no approval before the challenge expired",
				meta.SessionID, MethodPasswordMFA, meta.Login)
			return nil, fmt.Errorf("%s: %w: no second-factor approval before the challenge expired", op, ErrDenied)
		}

		resp, err := a.opts.Client.PollMFA(ctx, &mgmt.MFAPollRequest{
			Token: challenge.Token,
			Conn:  meta.wire(now),
		})
		if err != nil {
			outcome := classify(op, err)
			a.opts.logf("auth: session=%s method=%s login=%q: %v",
				meta.SessionID, MethodPasswordMFA, meta.Login, outcome)
			return nil, outcome
		}

		switch resp.Status {
		case mgmt.AuthStatusAuthenticated:
			a.opts.logf("auth: session=%s method=%s login=%q: approved after %s",
				meta.SessionID, MethodPasswordMFA, meta.Login, now.Sub(start).Round(time.Millisecond))
			return a.accept(op, meta, resp.Identity, now)
		case mgmt.AuthStatusMFARequired:
			if resp.MFA != nil {
				// The server may re-state its pacing between polls; honour it.
				interval = a.pollInterval(resp.MFA)
			}
			if a.mfa.ProgressInterval > 0 && !now.Before(lastProgress.Add(a.mfa.ProgressInterval)) {
				lastProgress = now
				if err := prompter.Waiting(waitingText(instruction, now.Sub(start)), now.Sub(start)); err != nil {
					return nil, fmt.Errorf("%s: %w: %w", op, ErrUnavailable, err)
				}
			}
		default:
			outcome := fmt.Errorf("%s: %w: unexpected status %q while polling", op, ErrUnavailable, resp.Status)
			a.opts.logf("auth: session=%s method=%s login=%q: %v",
				meta.SessionID, MethodPasswordMFA, meta.Login, outcome)
			return nil, outcome
		}
	}
}

// pollInterval is the server's requested pacing, floored by MinPollInterval.
func (a *PasswordMFAAuthenticator) pollInterval(challenge *mgmt.MFAChallenge) time.Duration {
	d := challenge.PollAfter()
	if d < a.mfa.MinPollInterval {
		return a.mfa.MinPollInterval
	}
	return d
}

// sleep waits for d or until ctx ends, whichever is first.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
