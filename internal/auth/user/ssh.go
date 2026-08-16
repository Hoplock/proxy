// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package user

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mauroasilva/securecommandproxy/internal/identity"
)

// ssh.Permissions extension keys. Permissions is the only value x/crypto/ssh
// carries from an authentication callback to the accepted connection, and it is
// server-side only — it is never sent to the client — which makes it the right
// place to hand the authenticated identity to the proxy (0005).
const (
	// ExtensionIdentity holds the authenticated identity, JSON-encoded.
	ExtensionIdentity = "securecommandproxy-identity"
	// ExtensionAuthMethod holds the method that authenticated the connection.
	ExtensionAuthMethod = "securecommandproxy-auth-method"
	// ExtensionSessionID holds the bastion-assigned session id, so the proxy
	// and the log pipeline use the same id the auth calls already used.
	ExtensionSessionID = "securecommandproxy-session-id"
)

// PasswordPrompt is the keyboard-interactive question that collects the
// password. It ends in a space because SSH clients print it verbatim.
const PasswordPrompt = "Password: "

// ConnMetaFunc derives the metadata for one connection's authentication from
// the SSH connection metadata.
//
// It is supplied by the caller rather than computed here because splitting the
// SSH username into login and target is routing's job (D1), and this phase must
// not grow a second implementation of it. Use ConnMetaFromSSH to fill in the
// transport fields.
type ConnMetaFunc func(ssh.ConnMetadata) ConnMeta

// ConnMetaFromSSH copies the transport-level fields of an SSH connection into
// base and returns the result. It deliberately does not touch Login or Target:
// those come from parsing the SSH username, which the caller owns.
func ConnMetaFromSSH(base ConnMeta, conn ssh.ConnMetadata) ConnMeta {
	if conn == nil {
		return base
	}
	if conn.RemoteAddr() != nil {
		base.ClientAddr = conn.RemoteAddr().String()
	}
	if conn.LocalAddr() != nil {
		base.ServerAddr = conn.LocalAddr().String()
	}
	base.ClientVersion = string(conn.ClientVersion())
	return base
}

// ServerAuthOptions configures a ServerAuth.
type ServerAuthOptions struct {
	// Authenticator decides. Required; normally a *Registry.
	Authenticator UserAuthenticator
	// ConnMeta derives the per-connection metadata. Required.
	ConnMeta ConnMetaFunc
	// BaseContext bounds every authentication call. Nil means
	// context.Background().
	//
	// x/crypto/ssh gives its auth callbacks no context, so per-connection
	// cancellation cannot be wired here; the listener owns it (0005), and the
	// listener's context is what belongs in this field.
	BaseContext context.Context
	// Banner overrides the pre-authentication banner. Nil means BannerMessage.
	// Returning "" suppresses the banner.
	Banner func(meta ConnMeta) string
}

// ServerAuth adapts a UserAuthenticator to the golang.org/x/crypto/ssh server
// callbacks. It is the whole of this phase's SSH surface: it authenticates and
// hands the resulting identity to the connection, and it does not accept
// channels, dial targets, or know that a target exists — that is the proxy
// engine (0005).
//
// Everything it tells the user follows PLAN §4.3: a banner before the wait so
// the pause is explicable, keyboard-interactive instructions during an MFA
// wait, and, on failure, a message that distinguishes a deny from an outage
// without revealing which credential or target was involved.
type ServerAuth struct {
	auth     UserAuthenticator
	connMeta ConnMetaFunc
	ctx      context.Context
	banner   func(ConnMeta) string
}

// NewServerAuth validates opts and returns the SSH auth adapter.
func NewServerAuth(opts ServerAuthOptions) (*ServerAuth, error) {
	if opts.Authenticator == nil {
		return nil, errors.New("auth/user: ServerAuth requires an authenticator")
	}
	if opts.ConnMeta == nil {
		return nil, errors.New("auth/user: ServerAuth requires a ConnMeta function")
	}
	a := &ServerAuth{
		auth:     opts.Authenticator,
		connMeta: opts.ConnMeta,
		ctx:      opts.BaseContext,
		banner:   opts.Banner,
	}
	if a.ctx == nil {
		a.ctx = context.Background()
	}
	if a.banner == nil {
		a.banner = func(m ConnMeta) string { return BannerMessage(m.SessionID) }
	}
	return a, nil
}

// Apply installs the authentication callbacks on cfg.
//
// Only the methods the authenticator actually supports are offered: advertising
// keyboard-interactive on a certificate-only bastion would prompt every user
// for a password that can never succeed. NoClientAuth is forced off — an
// unauthenticated session has no identity to authorize, log, or revoke.
func (a *ServerAuth) Apply(cfg *ssh.ServerConfig) {
	cfg.NoClientAuth = false
	cfg.BannerCallback = a.BannerCallback

	flows, declared := a.auth.(FlowSupport)
	if !declared || flows.SupportsCert() {
		cfg.PublicKeyCallback = a.PublicKeyCallback
	}
	if !declared || flows.SupportsPassword() {
		cfg.KeyboardInteractiveCallback = a.KeyboardInteractiveCallback
	}
}

// BannerCallback implements ssh.ServerConfig.BannerCallback. It runs before any
// authentication method, which is exactly when the user is about to wait on a
// remote decision they cannot see.
func (a *ServerAuth) BannerCallback(conn ssh.ConnMetadata) string {
	return a.banner(a.connMeta(conn))
}

// PublicKeyCallback implements ssh.ServerConfig.PublicKeyCallback: the
// certificate-first half of PLAN §4.1.
//
// A failure here is not the end of the conversation — the SSH client goes on to
// offer its next key and then keyboard-interactive, which is how the fallback to
// password+MFA happens — so the message attached to a deny is intentionally the
// same generic line the final failure carries.
func (a *ServerAuth) PublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	meta := a.connMeta(conn)
	id, err := a.auth.AuthenticateCert(a.ctx, meta, key)
	if err != nil {
		return nil, authFailure(err, meta)
	}
	return permissionsFor(id, meta)
}

// KeyboardInteractiveCallback implements
// ssh.ServerConfig.KeyboardInteractiveCallback: the password+MFA fallback.
//
// The password is collected over keyboard-interactive rather than plain
// password auth for one structural reason (PLAN §4.3): keyboard-interactive is
// the only flow with an instruction field, and a zero-prompt info request is
// the only way to say anything to the user while an out-of-band approval is
// outstanding. Plain password auth would leave the user staring at a frozen
// terminal for as long as the phone takes.
func (a *ServerAuth) KeyboardInteractiveCallback(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	meta := a.connMeta(conn)

	answers, err := challenge("", "", []string{PasswordPrompt}, []bool{false})
	if err != nil {
		// The client refused or dropped the prompt: no decision was reached, so
		// this is not a deny.
		return nil, fmt.Errorf("keyboard-interactive: %w: %w", ErrUnavailable, err)
	}
	if len(answers) != 1 {
		return nil, fmt.Errorf("keyboard-interactive: %w: client answered %d prompts, want 1",
			ErrUnavailable, len(answers))
	}

	ctx := WithMFAPrompter(a.ctx, &challengePrompter{challenge: challenge})
	id, err := a.auth.AuthenticatePassword(ctx, meta, answers[0])
	// answers[0] is the password: it is passed on and never retained, logged, or
	// wrapped into an error anywhere below this line (PLAN §7).
	if err != nil {
		return nil, authFailure(err, meta)
	}
	return permissionsFor(id, meta)
}

// authFailure attaches the user-visible text to the error handed back to the
// SSH layer. ssh.BannerError is what makes the text reach the client: it is
// sent as SSH_MSG_USERAUTH_BANNER before the failure, which is the difference
// between "access denied" and a connection that simply stops.
func authFailure(err error, meta ConnMeta) error {
	return &ssh.BannerError{
		Err:     err,
		Message: FailureMessage(err, meta.SessionID) + "\r\n",
	}
}

// permissionsFor packs the authenticated identity into the value x/crypto/ssh
// carries into the accepted connection.
func permissionsFor(id *identity.Identity, meta ConnMeta) (*ssh.Permissions, error) {
	encoded, err := json.Marshal(id)
	if err != nil {
		// Unreachable for a well-formed identity, but failing closed here is the
		// only safe answer: a connection whose identity the proxy cannot read
		// could not be authorized or audited.
		return nil, fmt.Errorf("auth/user: %w: encode identity: %w", ErrUnavailable, err)
	}
	return &ssh.Permissions{
		Extensions: map[string]string{
			ExtensionIdentity:   string(encoded),
			ExtensionAuthMethod: string(id.Method),
			ExtensionSessionID:  meta.SessionID,
		},
	}, nil
}

// IdentityFromPermissions recovers the identity ServerAuth attached to an
// authenticated connection. The proxy (0005) calls it on
// ssh.ServerConn.Permissions to learn who it is proxying for.
func IdentityFromPermissions(perms *ssh.Permissions) (*identity.Identity, error) {
	if perms == nil || perms.Extensions == nil {
		return nil, fmt.Errorf("auth/user: %w: connection carries no permissions", identity.ErrIncomplete)
	}
	encoded, ok := perms.Extensions[ExtensionIdentity]
	if !ok {
		return nil, fmt.Errorf("auth/user: %w: connection carries no identity", identity.ErrIncomplete)
	}
	var id identity.Identity
	if err := json.Unmarshal([]byte(encoded), &id); err != nil {
		return nil, fmt.Errorf("auth/user: decode identity: %w", err)
	}
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return &id, nil
}

// SessionIDFromPermissions recovers the session id ServerAuth attached to an
// authenticated connection.
func SessionIDFromPermissions(perms *ssh.Permissions) string {
	if perms == nil {
		return ""
	}
	return perms.Extensions[ExtensionSessionID]
}

// challengePrompter speaks to the user over an open keyboard-interactive
// exchange. Every message is a request with no questions, which SSH clients
// render as text and answer with an empty list — that is the mechanism for
// saying something mid-authentication without asking for anything.
type challengePrompter struct {
	challenge ssh.KeyboardInteractiveChallenge
}

var _ MFAPrompter = (*challengePrompter)(nil)

// Challenge shows the server's MFA prompt.
func (p *challengePrompter) Challenge(instruction string) error {
	return p.send(instruction)
}

// Waiting shows a "still waiting" line so a slow approval is visibly progress
// rather than a hang.
func (p *challengePrompter) Waiting(instruction string, _ time.Duration) error {
	return p.send(instruction)
}

func (p *challengePrompter) send(instruction string) error {
	_, err := p.challenge("", instruction+"\r\n", nil, nil)
	return err
}
