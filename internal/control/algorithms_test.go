// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestDefaultIsTheLibrarysSecureSet is the tripwire the rule "default follows
// the library's secure classification" rests on. A library upgrade that moves
// an algorithm between its supported and insecure lists fails here, so the
// change to what every default route offers is reviewed rather than absorbed.
func TestDefaultIsTheLibrarysSecureSet(t *testing.T) {
	got := AlgorithmProfileDefault.Algorithms()
	want := ssh.SupportedAlgorithms()
	for _, axis := range []struct {
		name      string
		got, want []string
	}{
		{"key exchange", got.KeyExchanges, want.KeyExchanges},
		{"cipher", got.Ciphers, want.Ciphers},
		{"MAC", got.MACs, want.MACs},
		{"host key", got.HostKeys, want.HostKeys},
		{"public-key auth", got.PublicKeyAuths, want.PublicKeyAuths},
	} {
		if !slices.Equal(axis.got, axis.want) {
			t.Errorf("default %s list = %q, the library's supported set is %q — a library upgrade moved "+
				"an algorithm; review the change and update internal/control/algorithms.go",
				axis.name, axis.got, axis.want)
		}
	}
}

// TestDefaultPinsTheExactLists pins the lists themselves, so a change to the
// secure set is a diff somebody reads even if the library comparison above were
// ever relaxed.
func TestDefaultPinsTheExactLists(t *testing.T) {
	a := AlgorithmProfileDefault.Algorithms()
	pins := map[string][2][]string{
		"key exchange": {a.KeyExchanges, {"mlkem768x25519-sha256", "curve25519-sha256", "ecdh-sha2-nistp256",
			"ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group14-sha256",
			"diffie-hellman-group16-sha512", "diffie-hellman-group-exchange-sha256"}},
		"cipher": {a.Ciphers, {"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
			"chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr"}},
		"MAC": {a.MACs, {"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
			"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"}},
		"host key": {a.HostKeys, {"rsa-sha2-256-cert-v01@openssh.com", "rsa-sha2-512-cert-v01@openssh.com",
			"ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com",
			"ecdsa-sha2-nistp521-cert-v01@openssh.com", "ssh-ed25519-cert-v01@openssh.com",
			"rsa-sha2-256", "rsa-sha2-512", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
			"ecdsa-sha2-nistp521", "ssh-ed25519"}},
		"public-key auth": {a.PublicKeyAuths, {"ssh-ed25519", "sk-ssh-ed25519@openssh.com",
			"sk-ecdsa-sha2-nistp256@openssh.com", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
			"ecdsa-sha2-nistp521", "rsa-sha2-256", "rsa-sha2-512"}},
	}
	for axis, p := range pins {
		if !slices.Equal(p[0], p[1]) {
			t.Errorf("default %s list = %q, want %q", axis, p[0], p[1])
		}
	}

	// The four the owner's decision removes appear on NO axis.
	for _, banned := range []string{"diffie-hellman-group14-sha1", "hmac-sha1-96", "ssh-rsa", "ssh-dss"} {
		for _, list := range [][]string{a.KeyExchanges, a.Ciphers, a.MACs, a.HostKeys, a.PublicKeyAuths} {
			if slices.Contains(list, banned) {
				t.Errorf("default offers %q", banned)
			}
		}
	}
}

// TestLegacyProfilesAddExactlyWhatTheySayAfterEverySecureEntry checks both
// legacy expansions against the secure set: every secure entry first, in the
// library's order, then exactly the additions the contract names.
func TestLegacyProfilesAddExactlyWhatTheySayAfterEverySecureEntry(t *testing.T) {
	secure := AlgorithmProfileDefault.Algorithms()
	cases := []struct {
		profile AlgorithmProfile
		kex     []string
		ciphers []string
		macs    []string
		hosts   []string
		pubkeys []string
	}{
		{
			profile: AlgorithmProfileLegacyRSASHA1,
			hosts:   []string{"ssh-rsa-cert-v01@openssh.com", "ssh-rsa"},
			pubkeys: []string{"ssh-rsa"},
		},
		{
			profile: AlgorithmProfileLegacyDevice,
			kex:     []string{"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"},
			ciphers: []string{"aes128-cbc", "3des-cbc"},
			macs:    []string{"hmac-sha1-96"},
			// RSA-SHA1, then DSA, in that order, after every secure entry.
			hosts:   []string{"ssh-rsa-cert-v01@openssh.com", "ssh-rsa", "ssh-dss-cert-v01@openssh.com", "ssh-dss"},
			pubkeys: []string{"ssh-rsa"},
		},
	}
	for _, c := range cases {
		got := c.profile.Algorithms()
		for _, axis := range []struct {
			name              string
			got, secure, adds []string
		}{
			{"key exchange", got.KeyExchanges, secure.KeyExchanges, c.kex},
			{"cipher", got.Ciphers, secure.Ciphers, c.ciphers},
			{"MAC", got.MACs, secure.MACs, c.macs},
			{"host key", got.HostKeys, secure.HostKeys, c.hosts},
			{"public-key auth", got.PublicKeyAuths, secure.PublicKeyAuths, c.pubkeys},
		} {
			want := append(append([]string(nil), axis.secure...), axis.adds...)
			if !slices.Equal(axis.got, want) {
				t.Errorf("%s %s list = %q, want %q", c.profile, axis.name, axis.got, want)
			}
		}
	}

	// No RC4, and no DSA for authentication, under any profile.
	for _, p := range []AlgorithmProfile{AlgorithmProfileDefault, AlgorithmProfileLegacyRSASHA1, AlgorithmProfileLegacyDevice} {
		a := p.Algorithms()
		for _, c := range a.Ciphers {
			if c == "arcfour" || c == "arcfour128" || c == "arcfour256" {
				t.Errorf("%s offers RC4 cipher %q", p, c)
			}
		}
		if slices.Contains(a.PublicKeyAuths, "ssh-dss") {
			t.Errorf("%s would authenticate with DSA", p)
		}
	}
}

// Every legacy addition must be something the library can actually negotiate;
// a name it does not know is silently dropped by ssh.Config.SetDefaults, which
// would make a profile narrower than the record says.
func TestEveryExpandedAlgorithmIsImplemented(t *testing.T) {
	sup, ins := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()
	known := func(lists ...[]string) map[string]bool {
		m := map[string]bool{}
		for _, l := range lists {
			for _, a := range l {
				m[a] = true
			}
		}
		return m
	}
	a := AlgorithmProfileLegacyDevice.Algorithms()
	for _, axis := range []struct {
		name  string
		got   []string
		known map[string]bool
	}{
		{"key exchange", a.KeyExchanges, known(sup.KeyExchanges, ins.KeyExchanges)},
		{"cipher", a.Ciphers, known(sup.Ciphers, ins.Ciphers)},
		{"MAC", a.MACs, known(sup.MACs, ins.MACs)},
		{"host key", a.HostKeys, known(sup.HostKeys, ins.HostKeys)},
		{"public-key auth", a.PublicKeyAuths, known(sup.PublicKeyAuths, ins.PublicKeyAuths)},
	} {
		for _, name := range axis.got {
			if !axis.known[name] {
				t.Errorf("%s %q is not implemented by x/crypto/ssh", axis.name, name)
			}
		}
	}
}

func TestExpansionSharesNoSliceBetweenCalls(t *testing.T) {
	a := AlgorithmProfileLegacyDevice.Algorithms()
	a.KeyExchanges[0] = "mutated"
	if AlgorithmProfileLegacyDevice.Algorithms().KeyExchanges[0] == "mutated" {
		t.Fatal("the expansion returned a shared slice")
	}
	c := a.Clone()
	c.HostKeys[0] = "clone-mutated"
	if a.HostKeys[0] == "clone-mutated" {
		t.Fatal("Clone shares a slice")
	}
	if !(Algorithms{}).IsZero() || a.IsZero() {
		t.Fatal("IsZero is wrong")
	}
	if AlgorithmProfile("").Resolve() != AlgorithmProfileDefault || AlgorithmProfileLegacyDevice.Resolve() != AlgorithmProfileLegacyDevice {
		t.Fatal("Resolve is wrong")
	}
}
