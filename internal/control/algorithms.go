// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

// Algorithms is what one SSH connection on the proxy→target leg may offer, one
// list per negotiated axis, in preference order (phase 0043).
//
// It is plain strings on purpose: this package stays free of
// golang.org/x/crypto/ssh, and the two packages that apply these lists —
// internal/proxy for the session leg, internal/auth/target and its device
// subpackage for every connection the credential plane opens — may not import
// each other. So the expansion lives here, once, and each of them turns it into
// an ssh.ClientConfig (internal/sshalg).
//
// The zero value means "no algorithms were handed down", never "offer
// nothing"; the one applier fills an empty axis from the default profile, so a
// connection can never fall through to the library's own client defaults — the
// set this type exists to replace (see AlgorithmProfileDefault).
type Algorithms struct {
	// KeyExchanges are the key-exchange methods.
	KeyExchanges []string
	// Ciphers apply in both directions.
	Ciphers []string
	// MACs apply in both directions.
	MACs []string
	// HostKeys are the host-key algorithms the target may present.
	HostKeys []string
	// PublicKeyAuths are the signature algorithms the proxy may sign a
	// public-key authentication with. x/crypto has no client-side field for
	// this axis, so it is applied by restricting each signer.
	PublicKeyAuths []string
}

// IsZero reports whether no axis carries a list.
func (a Algorithms) IsZero() bool {
	return len(a.KeyExchanges) == 0 && len(a.Ciphers) == 0 && len(a.MACs) == 0 &&
		len(a.HostKeys) == 0 && len(a.PublicKeyAuths) == 0
}

// Clone returns a copy that shares no slice with a.
func (a Algorithms) Clone() Algorithms {
	return Algorithms{
		KeyExchanges:   cloneStrings(a.KeyExchanges),
		Ciphers:        cloneStrings(a.Ciphers),
		MACs:           cloneStrings(a.MACs),
		HostKeys:       cloneStrings(a.HostKeys),
		PublicKeyAuths: cloneStrings(a.PublicKeyAuths),
	}
}

// The secure set: golang.org/x/crypto/ssh's SupportedAlgorithms(), axis by
// axis, in the library's own order, as of the version go.mod pins (v0.56.0).
//
// They are written out rather than read from the library at run time, and that
// is the point. The rule is "default follows the library's secure
// classification", but a library upgrade that moves an algorithm between its
// supported and insecure lists changes what every default route offers, and
// that must be a reviewed change and not one absorbed by `go get`.
// TestDefaultIsTheLibrarysSecureSet compares these lists to the library and
// fails the build the day they differ.
//
// What that excludes, compared with the library's CLIENT DEFAULTS that nothing
// here overrode before phase 0043: `diffie-hellman-group14-sha1` (a SHA-1 key
// exchange), `hmac-sha1-96`, and the `ssh-rsa` / `ssh-dss` host keys and their
// certificate forms. What it keeps and says so: `hmac-sha1`, which the library
// classes as supported — HMAC with SHA-1 is not broken the way a SHA-1
// signature is. Phase 0045's bans are how an administrator removes it.
var (
	secureKeyExchanges = []string{
		"mlkem768x25519-sha256",
		"curve25519-sha256",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
		"diffie-hellman-group14-sha256",
		"diffie-hellman-group16-sha512",
		"diffie-hellman-group-exchange-sha256",
	}
	secureCiphers = []string{
		"aes128-gcm@openssh.com",
		"aes256-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"aes128-ctr",
		"aes192-ctr",
		"aes256-ctr",
	}
	secureMACs = []string{
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"hmac-sha2-256",
		"hmac-sha2-512",
		"hmac-sha1",
	}
	secureHostKeys = []string{
		"rsa-sha2-256-cert-v01@openssh.com",
		"rsa-sha2-512-cert-v01@openssh.com",
		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
		"ssh-ed25519-cert-v01@openssh.com",
		"rsa-sha2-256",
		"rsa-sha2-512",
		"ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521",
		"ssh-ed25519",
	}
	securePublicKeyAuths = []string{
		"ssh-ed25519",
		"sk-ssh-ed25519@openssh.com",
		"sk-ecdsa-sha2-nistp256@openssh.com",
		"ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521",
		"rsa-sha2-256",
		"rsa-sha2-512",
	}
)

// What each legacy profile ADDS, and nothing else. Every addition goes after
// every secure entry on its axis, so a target that speaks anything modern
// negotiates it and the weakening is used only where it is the one thing the
// target has — phase 0045's floors and bans are written against that ordering.
var (
	// RSA with SHA-1 signatures: the host key (and its certificate form) and
	// the signature the proxy authenticates with.
	rsaSHA1HostKeys       = []string{"ssh-rsa-cert-v01@openssh.com", "ssh-rsa"}
	rsaSHA1PublicKeyAuths = []string{"ssh-rsa"}

	// legacy-device on top of that. The key exchanges are the library's
	// insecure SHA-1 set; the ciphers are its CBC modes and not RC4, because
	// the contract promises CBC and nothing more; the MAC is the truncated
	// SHA-1 one. DSA host keys are here because firmware old enough to need
	// SHA-1 key exchange is where DSA-only host keys live (the owner's
	// decision on PR #64). DSA is NOT added for public-key authentication: the
	// proxy's own keys are never DSA.
	legacyKeyExchanges = []string{
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
	}
	legacyCiphers  = []string{"aes128-cbc", "3des-cbc"}
	legacyMACs     = []string{"hmac-sha1-96"}
	dsaHostKeys    = []string{"ssh-dss-cert-v01@openssh.com", "ssh-dss"}
	legacyHostKeys = append(append([]string(nil), rsaSHA1HostKeys...), dsaHostKeys...)
)

// Algorithms expands the preset into the lists a connection offers. It is the
// ONE place a proxy→target connection's lists come from (phase 0043), and it
// always returns a list on every axis: an empty field is what lets the
// library's insecure client defaults back in.
//
// An unrecognised profile expands as the default. The contract refuses one
// before it reaches here (AuthorizeResponse.Validate), so this is only ever a
// programming error, and failing toward the narrowest set is the direction in
// which such an error costs a connection rather than a weakening.
func (p AlgorithmProfile) Algorithms() Algorithms {
	a := Algorithms{
		KeyExchanges:   cloneStrings(secureKeyExchanges),
		Ciphers:        cloneStrings(secureCiphers),
		MACs:           cloneStrings(secureMACs),
		HostKeys:       cloneStrings(secureHostKeys),
		PublicKeyAuths: cloneStrings(securePublicKeyAuths),
	}
	switch p {
	case AlgorithmProfileLegacyRSASHA1:
		a.HostKeys = append(a.HostKeys, rsaSHA1HostKeys...)
		a.PublicKeyAuths = append(a.PublicKeyAuths, rsaSHA1PublicKeyAuths...)
	case AlgorithmProfileLegacyDevice:
		a.KeyExchanges = append(a.KeyExchanges, legacyKeyExchanges...)
		a.Ciphers = append(a.Ciphers, legacyCiphers...)
		a.MACs = append(a.MACs, legacyMACs...)
		a.HostKeys = append(a.HostKeys, legacyHostKeys...)
		a.PublicKeyAuths = append(a.PublicKeyAuths, rsaSHA1PublicKeyAuths...)
	}
	return a
}

// Resolve is the profile a record should name for p: AlgorithmProfileDefault
// for the empty string, and p otherwise. It is AuthorizeResponse.Profile's
// rule for a value that has already left the response.
func (p AlgorithmProfile) Resolve() AlgorithmProfile {
	if p == "" {
		return AlgorithmProfileDefault
	}
	return p
}
