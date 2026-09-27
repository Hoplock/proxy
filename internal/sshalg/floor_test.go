// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package sshalg

import (
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/sshtest"
)

// This file is phase 0045's wire half: what a floor and a ban do to the offer is
// asserted on the KEXINIT the client really sends — after everything the
// library fills in — not on the expansion function alone.

// extensionSignals are not key exchanges; the library adds them to its own
// KEXINIT and a comparison of offers leaves them out.
var extensionSignals = []string{"ext-info-c", "kex-strict-c-v00@openssh.com"}

// offerFor dials a KEXINIT-recording target with cfg and returns what the client
// advertised.
func offerFor(t *testing.T, cfg *ssh.ClientConfig) sshtest.KexInit {
	t.Helper()
	tgt, err := sshtest.StartKexInitTarget(sshtest.KexInitDefaults(sshtest.KexInitOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tgt.Close() }()
	conn, err := net.DialTimeout("tcp", tgt.Addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	cfg.User = "probe"
	cfg.HostKeyCallback = ssh.InsecureIgnoreHostKey() //nolint:gosec // the target never presents a key
	if c, _, _, err := ssh.NewClientConn(conn, tgt.Addr(), cfg); err == nil {
		_ = c.Close()
	}
	_ = conn.Close()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if inits := tgt.ClientKexInits(); len(inits) > 0 {
			init := inits[0]
			init.KeyExchanges = slices.DeleteFunc(init.KeyExchanges, func(k string) bool { return slices.Contains(extensionSignals, k) })
			return init
		}
	}
	t.Fatal("the client sent no KEXINIT")
	return sshtest.KexInit{}
}

// acceptedPolicies is every profile × {no floor, each level} the contract
// accepts, with bans as given.
func acceptedPolicies(bans *control.AlgorithmBans) []control.AlgorithmPolicy {
	var out []control.AlgorithmPolicy
	for _, profile := range control.AlgorithmProfiles() {
		out = append(out, control.AlgorithmPolicy{Profile: profile, Bans: bans})
		if control.ProfileWidensKeyExchange(profile) {
			continue
		}
		for _, floor := range control.AlgorithmFloors() {
			out = append(out, control.AlgorithmPolicy{Profile: profile, Floor: floor, Bans: bans})
		}
	}
	return out
}

// TestAFloorIsExactlyItsLevelOnTheWire is the acceptance table: every profile ×
// {no floor, floor}, applied to a real ssh.ClientConfig and read back off the
// wire. Under a floor the key exchanges offered are EXACTLY the level's accepted
// set — under pq-hybrid-kex the hybrid alone — and every other axis is what the
// profile alone gives.
func TestAFloorIsExactlyItsLevelOnTheWire(t *testing.T) {
	for _, policy := range acceptedPolicies(nil) {
		var cfg ssh.ClientConfig
		Apply(&cfg, policy.Algorithms())
		got := offerFor(t, &cfg)
		name := string(policy.Profile) + " + " + string(policy.Floor)

		if !slices.Equal(got.KeyExchanges, policy.WireKeyExchanges()) {
			t.Errorf("%s: key exchanges on the wire %q, the policy says %q", name, got.KeyExchanges, policy.WireKeyExchanges())
		}
		if policy.Floor == control.AlgorithmFloorPQHybridKEX && !slices.Equal(got.KeyExchanges, []string{ssh.KeyExchangeMLKEM768X25519}) {
			t.Errorf("%s: offered %q, want the implemented hybrid alone", name, got.KeyExchanges)
		}
		alone := control.AlgorithmPolicy{Profile: policy.Profile}
		want := alone.Algorithms()
		if policy.Floor == "" {
			// No floor: the profile's own offer, key exchanges included.
			if !slices.Equal(got.KeyExchanges, alone.WireKeyExchanges()) {
				t.Errorf("%s: key exchanges %q, the profile alone offers %q", name, got.KeyExchanges, alone.WireKeyExchanges())
			}
		}
		for axis, pair := range map[string][2][]string{
			"host keys":     {got.HostKeys, want.HostKeys},
			"ciphers (c→s)": {got.CiphersClientServer, want.Ciphers},
			"ciphers (s→c)": {got.CiphersServerClient, want.Ciphers},
			"MACs (c→s)":    {got.MACsClientServer, want.MACs},
			"MACs (s→c)":    {got.MACsServerClient, want.MACs},
		} {
			if !slices.Equal(pair[0], pair[1]) {
				t.Errorf("%s: %s on the wire %q, the profile alone gives %q", name, axis, pair[0], pair[1])
			}
		}
	}
}

// TestLegacyDeviceOffersEverySHA1ExchangeLast, on the wire.
func TestLegacyDeviceOffersEverySHA1ExchangeLast(t *testing.T) {
	var cfg ssh.ClientConfig
	Apply(&cfg, control.AlgorithmPolicy{Profile: control.AlgorithmProfileLegacyDevice}.Algorithms())
	kex := offerFor(t, &cfg).KeyExchanges
	seenSHA1 := false
	for _, k := range kex {
		insecure := slices.Contains(ssh.InsecureAlgorithms().KeyExchanges, k)
		if seenSHA1 && !insecure {
			t.Fatalf("legacy-device offered modern %q after a SHA-1 exchange: %q", k, kex)
		}
		seenSHA1 = seenSHA1 || insecure
	}
	if !seenSHA1 {
		t.Fatalf("legacy-device offered no SHA-1 exchange: %q", kex)
	}
}

// TestABanIsExactlyWhatComesOffTheWire is the bans table over profile × floor
// × a ban on EVERY axis: the applied configuration offers exactly the unbanned
// part of what the route would otherwise offer, a ban wins over what a profile
// adds, the public-key axis is restricted on the signer, and an axis with no
// ban is byte-for-byte what it was without the feature.
func TestABanIsExactlyWhatComesOffTheWire(t *testing.T) {
	bans := &control.AlgorithmBans{
		KeyExchanges:   []string{"ecdh-sha2-nistp256", "diffie-hellman-group14-sha1", "curve25519-sha256@libssh.org"},
		Ciphers:        []string{"aes128-ctr", "aes128-cbc"},
		MACs:           []string{"hmac-sha1", "hmac-sha1-96"},
		HostKeys:       []string{"ecdsa-sha2-nistp521", "ssh-rsa"},
		PublicKeyAuths: []string{"rsa-sha2-256", "ssh-rsa"},
	}
	for _, policy := range acceptedPolicies(bans) {
		name := string(policy.Profile) + " + " + string(policy.Floor)
		unbanned := policy
		unbanned.Bans = nil
		var cfg ssh.ClientConfig
		Apply(&cfg, policy.Algorithms())
		got := offerFor(t, &cfg)

		strip := func(list, banned []string) []string {
			return slices.DeleteFunc(slices.Clone(list), func(n string) bool { return slices.Contains(banned, n) })
		}
		// The curve25519 alias ban removes both spellings (the library cannot
		// offer one without the other).
		wantKex := strip(unbanned.WireKeyExchanges(), append(bans.KeyExchanges, "curve25519-sha256"))
		want := unbanned.Algorithms()
		for axis, pair := range map[string][2][]string{
			"key exchanges": {got.KeyExchanges, wantKex},
			"host keys":     {got.HostKeys, strip(want.HostKeys, bans.HostKeys)},
			"ciphers":       {got.CiphersClientServer, strip(want.Ciphers, bans.Ciphers)},
			"MACs":          {got.MACsServerClient, strip(want.MACs, bans.MACs)},
		} {
			if !slices.Equal(pair[0], pair[1]) {
				t.Errorf("%s: %s on the wire %q, want %q", name, axis, pair[0], pair[1])
			}
		}
		for _, banned := range []string{"diffie-hellman-group14-sha1", "aes128-cbc", "hmac-sha1-96", "ssh-rsa"} {
			// What legacy-device ADDS, banned: the ban wins.
			for _, list := range [][]string{got.KeyExchanges, got.CiphersClientServer, got.MACsClientServer, got.HostKeys} {
				if slices.Contains(list, banned) {
					t.Errorf("%s: the ban on %q lost to the profile", name, banned)
				}
			}
		}

		// The public-key axis: an RSA key now signs with rsa-sha2-512 alone.
		signed := SignerAlgorithms(Signer(rsaSigner(t), policy.Algorithms()))
		if !slices.Equal(signed, []string{ssh.KeyAlgoRSASHA512}) {
			t.Errorf("%s: an RSA key offers %q under the ban, want [rsa-sha2-512]", name, signed)
		}
	}

	// One axis banned: every other axis is byte-for-byte unchanged.
	for _, policy := range acceptedPolicies(&control.AlgorithmBans{Ciphers: []string{"aes128-ctr"}}) {
		unbanned := policy
		unbanned.Bans = nil
		var with, without ssh.ClientConfig
		Apply(&with, policy.Algorithms())
		Apply(&without, unbanned.Algorithms())
		a, b := offerFor(t, &with), offerFor(t, &without)
		if !slices.Equal(a.KeyExchanges, b.KeyExchanges) || !slices.Equal(a.HostKeys, b.HostKeys) ||
			!slices.Equal(a.MACsClientServer, b.MACsClientServer) {
			t.Errorf("%s + %s: a cipher ban changed another axis on the wire", policy.Profile, policy.Floor)
		}
	}

	// A ban on something the route never offers changes nothing on the wire.
	var plain, banned ssh.ClientConfig
	Apply(&plain, control.AlgorithmPolicy{}.Algorithms())
	Apply(&banned, control.AlgorithmPolicy{Bans: &control.AlgorithmBans{KeyExchanges: []string{"diffie-hellman-group1-sha1"}}}.Algorithms())
	if a, b := offerFor(t, &plain), offerFor(t, &banned); !slices.Equal(a.KeyExchanges, b.KeyExchanges) {
		t.Errorf("banning an exchange default never offers changed the offer: %q vs %q", a.KeyExchanges, b.KeyExchanges)
	}
}

// TestNegotiatedIsReadOffTheConnection: the record's negotiated algorithms come
// from the established connection, in the proxy's direction.
func TestNegotiatedIsReadOffTheConnection(t *testing.T) {
	tgt, err := sshtest.StartTarget(sshtest.Options{Negotiation: sshtest.Negotiation{
		Ciphers: []string{"aes256-ctr"}, MACs: []string{"hmac-sha2-512"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tgt.Close() }()

	signer := sshtest.MustGenerateSigner()
	var cfg ssh.ClientConfig
	Apply(&cfg, control.AlgorithmPolicy{}.Algorithms())
	auth, offered := PublicKeys(signer, control.AlgorithmPolicy{}.Algorithms())
	cfg.User, cfg.Auth = "probe", []ssh.AuthMethod{auth}
	cfg.HostKeyCallback = ssh.InsecureIgnoreHostKey() //nolint:gosec // a test target
	client, err := ssh.Dial("tcp", net.JoinHostPort(tgt.Host(), strconv.Itoa(tgt.Port())), &cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	n, ok := NegotiatedOn(client.Conn)
	if !ok {
		t.Fatal("the connection exposes no negotiated algorithms")
	}
	if n.KeyExchange != ssh.KeyExchangeMLKEM768X25519 || n.CipherOut != "aes256-ctr" || n.CipherIn != "aes256-ctr" ||
		n.MACOut != "hmac-sha2-512" || n.MACIn != "hmac-sha2-512" || n.HostKey == "" {
		t.Errorf("negotiated %+v", n)
	}
	if !slices.Equal(offered, []string{ssh.KeyAlgoED25519}) {
		t.Errorf("an ed25519 key offers %q", offered)
	}
}
