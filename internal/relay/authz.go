// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package relay

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ErrUnauthorizedProxy means the key offered by a registering proxy is not
// trusted for the proxy id it claimed.
var ErrUnauthorizedProxy = errors.New("relay: the offered key is not authorized for that proxy id")

// permissionProxyID is the extension the authenticator records the validated
// proxy id in, so the registration is keyed by what was PROVEN rather than by
// what was claimed.
const permissionProxyID = "hoplock-proxy-id"

// AuthorizerOptions configures who may register a relay.
//
// At least one of the two sources is required, and they answer the same
// question in the two ways an SSH fleet already answers it: a certificate
// signed by the fleet's CA, or a key listed by hand. Nothing here is a new
// scheme — a registration is an inbound path into this proxy's routing, and
// inventing a bespoke shared secret for it would be the weakest link in a
// system whose every other credential is an SSH key.
type AuthorizerOptions struct {
	// AuthorizedKeysPath is an OpenSSH authorized_keys file. THE COMMENT ON
	// EACH LINE IS THE PROXY ID that key may register as: a key with no
	// comment is refused at load time, because a key that names no id would
	// be a key that can register as any id.
	AuthorizedKeysPath string
	// TrustedCAPath is a file of OpenSSH public keys, one per line, trusted to
	// sign the user certificates registering proxies present. A certificate is
	// accepted when it is signed by one of them, is currently valid, and lists
	// the claimed proxy id among its principals.
	TrustedCAPath string
	// Now overrides the clock certificate validity is checked against (tests).
	Now func() time.Time
}

// Authorizer decides whether a registering proxy may claim a proxy id.
type Authorizer struct {
	keys    map[string]string // key fingerprint → proxy id
	checker *ssh.CertChecker
	hasCA   bool
}

// NewAuthorizer loads the trusted material named by opts.
func NewAuthorizer(opts AuthorizerOptions) (*Authorizer, error) {
	if opts.AuthorizedKeysPath == "" && opts.TrustedCAPath == "" {
		return nil, errors.New("relay: accepting registrations needs an authorized_keys file or a trusted CA")
	}
	a := &Authorizer{keys: make(map[string]string)}

	if opts.AuthorizedKeysPath != "" {
		if err := a.loadAuthorizedKeys(opts.AuthorizedKeysPath); err != nil {
			return nil, err
		}
	}
	if opts.TrustedCAPath != "" {
		authorities, err := loadPublicKeys(opts.TrustedCAPath)
		if err != nil {
			return nil, err
		}
		if len(authorities) == 0 {
			return nil, fmt.Errorf("relay: trusted CA file %q contains no keys", opts.TrustedCAPath)
		}
		a.hasCA = true
		a.checker = &ssh.CertChecker{
			IsUserAuthority: func(auth ssh.PublicKey) bool {
				for _, ca := range authorities {
					if keysEqual(ca, auth) {
						return true
					}
				}
				return false
			},
		}
		if opts.Now != nil {
			a.checker.Clock = opts.Now
		}
	}
	return a, nil
}

// Authenticate is the PublicKeyCallback for the registration listener.
//
// The username a registering proxy presents is the id it claims; this is what
// decides whether it may. A certificate must name the id in its principals, and
// a bare key must be the one listed for that id — so a proxy authorized for one
// id can never register as another and start receiving its sessions.
func (a *Authorizer) Authenticate(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	claimed := conn.User()
	if claimed == "" {
		return nil, fmt.Errorf("%w: no proxy id was presented", ErrUnauthorizedProxy)
	}

	if cert, ok := key.(*ssh.Certificate); ok {
		if !a.hasCA {
			return nil, fmt.Errorf("%w: %q offered a certificate and no CA is trusted", ErrUnauthorizedProxy, claimed)
		}
		// CertChecker checks the signature, the validity window, the cert type,
		// and that conn.User() is among the principals.
		perms, err := a.checker.Authenticate(conn, cert)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnauthorizedProxy, err)
		}
		return withProxyID(perms, claimed), nil
	}

	if id, ok := a.keys[ssh.FingerprintSHA256(key)]; ok && id == claimed {
		return withProxyID(nil, claimed), nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnauthorizedProxy, claimed)
}

// ProxyIDOf returns the id the authenticator validated for a connection.
func ProxyIDOf(perms *ssh.Permissions) string {
	if perms == nil {
		return ""
	}
	return perms.Extensions[permissionProxyID]
}

func withProxyID(perms *ssh.Permissions, id string) *ssh.Permissions {
	if perms == nil {
		perms = &ssh.Permissions{}
	}
	if perms.Extensions == nil {
		perms.Extensions = make(map[string]string, 1)
	}
	perms.Extensions[permissionProxyID] = id
	return perms
}

func (a *Authorizer) loadAuthorizedKeys(path string) error {
	entries, err := parseKeyFile(path)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.comment == "" {
			return fmt.Errorf("relay: %s:%d has no comment; the comment names the proxy id the key may register as",
				path, e.line)
		}
		a.keys[ssh.FingerprintSHA256(e.key)] = e.comment
	}
	if len(a.keys) == 0 {
		return fmt.Errorf("relay: authorized keys %q contains no keys", path)
	}
	return nil
}

func loadPublicKeys(path string) ([]ssh.PublicKey, error) {
	entries, err := parseKeyFile(path)
	if err != nil {
		return nil, err
	}
	keys := make([]ssh.PublicKey, 0, len(entries))
	for _, e := range entries {
		keys = append(keys, e.key)
	}
	return keys, nil
}

// keyEntry is one usable line of a key file.
type keyEntry struct {
	key     ssh.PublicKey
	comment string
	line    int
}

// parseKeyFile reads an OpenSSH-format key file a line at a time.
//
// Line at a time, rather than by walking ParseAuthorizedKey's rest, because
// that walk cannot tell a trailing newline from a malformed entry: both end it
// with the same error and an empty remainder. A key file that silently loses a
// line decides who may register, so it fails loudly and names the line.
func parseKeyFile(path string) ([]keyEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("relay: read key file: %w", err)
	}
	var entries []keyEntry
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("relay: parse %s:%d: %w", path, i+1, err)
		}
		entries = append(entries, keyEntry{key: key, comment: strings.TrimSpace(comment), line: i + 1})
	}
	return entries, nil
}

func keysEqual(a, b ssh.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Type() == b.Type() && string(a.Marshal()) == string(b.Marshal())
}
