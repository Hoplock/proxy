// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// This file is phase 0045's half of the expansion: the floor ladder, the bans,
// and the rules that turn one handshake into a report of the target's level.
// Every expectation below is about the configured or wire lists as strings; the
// handshakes that put them on the wire are internal/proxy's and
// internal/sshalg's tests.

// TestTheLadderIsADial is the invariant that makes the floor something an
// administrator can turn up or down: every key exchange a level accepts is
// accepted by every level below it. A level added above the top that breaks it
// fails here, which is the contract's rule for adding a level.
func TestTheLadderIsADial(t *testing.T) {
	levels := AlgorithmFloors()
	if len(levels) < 2 {
		t.Fatalf("AlgorithmFloors() = %q, want the ladder", levels)
	}
	for i, level := range levels {
		if got := level.Rank(); got != i+1 {
			t.Errorf("%s.Rank() = %d, want %d: the order is AlgorithmFloors' and nothing else's", level, got, i+1)
		}
		if len(level.KeyExchanges()) == 0 {
			t.Errorf("%s accepts nothing", level)
		}
		for _, above := range levels[i+1:] {
			for _, kex := range above.KeyExchanges() {
				if !slices.Contains(level.KeyExchanges(), kex) {
					t.Errorf("%s accepts %q and %s, below it, does not: the levels must nest", above, kex, level)
				}
			}
		}
	}
	if AlgorithmFloor("").Rank() != 0 {
		t.Error("no floor must rank 0")
	}
	if AlgorithmFloor("fips-140").Rank() >= 0 {
		t.Error("an unknown level must not rank as no floor or as a level")
	}
}

// TestModernKEXIsTheLibrarysSupportedSet derives rank 1 from the library's own
// list and pins it: it is ssh.SupportedAlgorithms().KeyExchanges, and it is
// disjoint from the library's insecure (SHA-1) key exchanges. A library upgrade
// that moves either list fails here, and the table in api/README.md is updated
// to follow — the library wins.
func TestModernKEXIsTheLibrarysSupportedSet(t *testing.T) {
	got := AlgorithmFloorModernKEX.KeyExchanges()
	if want := ssh.SupportedAlgorithms().KeyExchanges; !slices.Equal(got, want) {
		t.Errorf("modern-kex accepts %q, the library's supported set is %q", got, want)
	}
	for _, insecure := range ssh.InsecureAlgorithms().KeyExchanges {
		if slices.Contains(got, insecure) {
			t.Errorf("modern-kex accepts the library's insecure %q", insecure)
		}
	}
	// The contract's own promise, independent of the library's classification.
	for _, kex := range got {
		if strings.Contains(kex, "sha1") {
			t.Errorf("modern-kex accepts %q, a SHA-1 key exchange", kex)
		}
	}
	if want := []string{
		"mlkem768x25519-sha256", "curve25519-sha256", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521", "diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
		"diffie-hellman-group-exchange-sha256",
	}; !slices.Equal(got, want) {
		t.Errorf("modern-kex = %q, want the pinned %q", got, want)
	}
}

// TestTheHybridIsTheLibrarysMLKEM holds the string this package carries (it may
// not import x/crypto) to the library's constant, and pins pq-hybrid-kex to it:
// x/crypto implements ML-KEM-768 hybrid and not sntrup761, so "either" in the
// request that asked for this is not something this proxy can honour.
func TestTheHybridIsTheLibrarysMLKEM(t *testing.T) {
	if KeyExchangeMLKEM768X25519 != ssh.KeyExchangeMLKEM768X25519 {
		t.Errorf("KeyExchangeMLKEM768X25519 = %q, the library's is %q", KeyExchangeMLKEM768X25519, ssh.KeyExchangeMLKEM768X25519)
	}
	if got := AlgorithmFloorPQHybridKEX.KeyExchanges(); !slices.Equal(got, []string{ssh.KeyExchangeMLKEM768X25519}) {
		t.Errorf("pq-hybrid-kex accepts %q, want exactly the ML-KEM hybrid", got)
	}
	for _, kex := range append(ssh.SupportedAlgorithms().KeyExchanges, ssh.InsecureAlgorithms().KeyExchanges...) {
		if strings.HasPrefix(kex, "sntrup761") {
			t.Errorf("the library now implements %q: add it to pq-hybrid-kex (a description change, not a vocabulary revision)", kex)
		}
	}
}

// TestTheWireModelMatchesTheLibrary holds wireKeyExchanges — this package's
// model of what the library ACTUALLY puts in KEXINIT — to the library, for every
// list any policy can produce: the pre-standard curve25519 alias is added after
// curve25519-sha256, and nowhere else.
func TestTheWireModelMatchesTheLibrary(t *testing.T) {
	lists := [][]string{
		AlgorithmFloorModernKEX.KeyExchanges(),
		AlgorithmFloorPQHybridKEX.KeyExchanges(),
		AlgorithmProfileLegacyDevice.Algorithms().KeyExchanges,
		{"curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256"},
		{"ecdh-sha2-nistp256"},
	}
	for _, list := range lists {
		cfg := ssh.Config{KeyExchanges: slices.Clone(list)}
		cfg.SetDefaults()
		if got := wireKeyExchanges(list); !slices.Equal(got, cfg.KeyExchanges) {
			t.Errorf("wireKeyExchanges(%q) = %q, the library offers %q", list, got, cfg.KeyExchanges)
		}
	}
}

// policies is every profile × floor combination the contract accepts, plus the
// no-floor case for each profile.
func policies() []AlgorithmPolicy {
	var out []AlgorithmPolicy
	for _, profile := range AlgorithmProfiles() {
		out = append(out, AlgorithmPolicy{Profile: profile})
		if ProfileWidensKeyExchange(profile) {
			continue
		}
		for _, floor := range AlgorithmFloors() {
			out = append(out, AlgorithmPolicy{Profile: profile, Floor: floor})
		}
	}
	return out
}

// TestAFloorOffersExactlyItsLevel is the acceptance table at the expansion's
// level (internal/sshalg asserts the same on an applied ssh.ClientConfig): under
// a floor the key-exchange list is EXACTLY that level's accepted set, and every
// other axis is what the profile alone gives.
func TestAFloorOffersExactlyItsLevel(t *testing.T) {
	for _, p := range policies() {
		got := p.Algorithms()
		alone := p.Profile.Algorithms()
		if p.Floor != "" {
			if want := p.Floor.KeyExchanges(); !slices.Equal(got.KeyExchanges, want) {
				t.Errorf("%s + %s offers key exchanges %q, want exactly %q", p.Profile, p.Floor, got.KeyExchanges, want)
			}
		}
		for axis, pair := range map[string][2][]string{
			"cipher":          {got.Ciphers, alone.Ciphers},
			"MAC":             {got.MACs, alone.MACs},
			"host key":        {got.HostKeys, alone.HostKeys},
			"public-key auth": {got.PublicKeyAuths, alone.PublicKeyAuths},
		} {
			if !slices.Equal(pair[0], pair[1]) {
				t.Errorf("%s + %q changed the %s axis: %q, the profile alone gives %q", p.Profile, p.Floor, axis, pair[0], pair[1])
			}
		}
	}
	// The pq floor is the hybrid ALONE, not "hybrids first": a list that went on
	// to classical exchanges would let the target pick one.
	if got := (AlgorithmPolicy{Floor: AlgorithmFloorPQHybridKEX}).Algorithms().KeyExchanges; !slices.Equal(got, []string{KeyExchangeMLKEM768X25519}) {
		t.Errorf("default + pq-hybrid-kex offers %q", got)
	}
}

// TestEveryOfferIsOrderedByLevel is what the target report's inference rests
// on: every key-exchange offer, floor or no floor, bans or no bans, lists the
// highest level's exchanges first — so under legacy-device every SHA-1 exchange
// comes after every modern one.
func TestEveryOfferIsOrderedByLevel(t *testing.T) {
	check := func(name string, kex []string) {
		t.Helper()
		for i := 1; i < len(kex); i++ {
			if KeyExchangeLevel(kex[i]).Rank() > KeyExchangeLevel(kex[i-1]).Rank() {
				t.Errorf("%s offers %q (%s) after %q (%s): the offer must be highest level first",
					name, kex[i], KeyExchangeLevel(kex[i]), kex[i-1], KeyExchangeLevel(kex[i-1]))
			}
		}
	}
	for _, p := range policies() {
		check(string(p.Profile)+"+"+string(p.Floor), p.WireKeyExchanges())
		p.Bans = &AlgorithmBans{KeyExchanges: []string{"ecdh-sha2-nistp256"}}
		check(string(p.Profile)+"+"+string(p.Floor)+"+ban", p.WireKeyExchanges())
	}

	legacy := AlgorithmPolicy{Profile: AlgorithmProfileLegacyDevice}.Algorithms().KeyExchanges
	firstSHA1 := slices.IndexFunc(legacy, func(k string) bool { return strings.Contains(k, "sha1") })
	if firstSHA1 < 0 {
		t.Fatalf("legacy-device offers no SHA-1 key exchange: %q", legacy)
	}
	for _, kex := range legacy[firstSHA1:] {
		if !strings.Contains(kex, "sha1") {
			t.Errorf("legacy-device offers modern %q after a SHA-1 exchange: %q", kex, legacy)
		}
	}
}

// allBans is a ban on every axis: something each profile offers, something
// only legacy-device offers, and something no build offers at all.
func allBans() *AlgorithmBans {
	return &AlgorithmBans{
		KeyExchanges:   []string{"diffie-hellman-group14-sha256", "diffie-hellman-group1-sha1", "sntrup761x25519-sha512"},
		Ciphers:        []string{"aes128-ctr", "aes128-cbc", "arcfour"},
		MACs:           []string{"hmac-sha1", "hmac-sha1-96"},
		HostKeys:       []string{"ssh-rsa", "ecdsa-sha2-nistp521"},
		PublicKeyAuths: []string{"ssh-rsa", "rsa-sha2-256"},
	}
}

// TestABanNeverAdds is the property the whole feature rests on, asserted over
// the whole table: for every profile × floor, the offer WITH bans is a subset of
// the offer without them, axis by axis, in the same order; a ban always wins
// over a profile's additions; and an axis with no ban is byte-for-byte what it
// was without the feature.
func TestABanNeverAdds(t *testing.T) {
	for _, p := range policies() {
		without := p.Algorithms()
		banned := p
		banned.Bans = allBans()
		with := banned.Algorithms()
		for _, axis := range []struct {
			name              string
			with, without, by []string
		}{
			{"key_exchanges", with.KeyExchanges, without.KeyExchanges, banned.Bans.KeyExchanges},
			{"ciphers", with.Ciphers, without.Ciphers, banned.Bans.Ciphers},
			{"macs", with.MACs, without.MACs, banned.Bans.MACs},
			{"host_keys", with.HostKeys, without.HostKeys, banned.Bans.HostKeys},
			{"public_key_auth", with.PublicKeyAuths, without.PublicKeyAuths, banned.Bans.PublicKeyAuths},
		} {
			// Exactly the unbanned names, in the order the route offered them.
			want := slices.DeleteFunc(slices.Clone(axis.without), func(n string) bool { return slices.Contains(axis.by, n) })
			if !slices.Equal(axis.with, want) {
				t.Errorf("%s + %q %s: with bans %q, want %q", p.Profile, p.Floor, axis.name, axis.with, want)
			}
		}

		// One axis banned, the rest untouched byte for byte.
		oneAxis := p
		oneAxis.Bans = &AlgorithmBans{Ciphers: []string{"aes128-ctr"}}
		got := oneAxis.Algorithms()
		if !slices.Equal(got.KeyExchanges, without.KeyExchanges) || !slices.Equal(got.MACs, without.MACs) ||
			!slices.Equal(got.HostKeys, without.HostKeys) || !slices.Equal(got.PublicKeyAuths, without.PublicKeyAuths) {
			t.Errorf("%s + %q: a cipher ban changed another axis", p.Profile, p.Floor)
		}
	}

	// A ban on something the route never offered changes nothing on the wire.
	def := AlgorithmPolicy{Profile: AlgorithmProfileDefault}
	onlyLegacy := def
	onlyLegacy.Bans = &AlgorithmBans{KeyExchanges: []string{"diffie-hellman-group1-sha1"}}
	if !slices.Equal(onlyLegacy.Algorithms().KeyExchanges, def.Algorithms().KeyExchanges) || onlyLegacy.KeyExchangeBanned() {
		t.Error("banning diffie-hellman-group1-sha1 under default changed the offer")
	}

	// A ban wins over what legacy-device adds.
	legacy := AlgorithmPolicy{Profile: AlgorithmProfileLegacyDevice, Bans: &AlgorithmBans{
		KeyExchanges: []string{"diffie-hellman-group14-sha1"}, HostKeys: []string{"ssh-dss"}}}
	if a := legacy.Algorithms(); slices.Contains(a.KeyExchanges, "diffie-hellman-group14-sha1") || slices.Contains(a.HostKeys, "ssh-dss") {
		t.Errorf("legacy-device's additions survived a ban: %+v", a)
	}
}

// TestBanningEitherCurve25519SpellingBansBoth: the library offers the libssh
// alias whenever it offers curve25519-sha256 and cannot be told otherwise, so
// the only way to honour a ban on either name is to remove both.
func TestBanningEitherCurve25519SpellingBansBoth(t *testing.T) {
	for _, name := range []string{"curve25519-sha256", "curve25519-sha256@libssh.org"} {
		p := AlgorithmPolicy{Bans: &AlgorithmBans{KeyExchanges: []string{name}}}
		for _, offered := range p.WireKeyExchanges() {
			if canonicalKeyExchange(offered) == kexCurve25519 {
				t.Errorf("a ban on %q left %q on the wire", name, offered)
			}
		}
		if unmatched := p.UnmatchedBans(); len(unmatched) != 0 {
			t.Errorf("a ban on %q was reported unmatched: %q — the library offers it", name, unmatched)
		}
	}
	if KeyExchangeLevel("curve25519-sha256@libssh.org") != AlgorithmFloorModernKEX {
		t.Error("a target negotiating the libssh alias met modern-kex")
	}
}

// TestUnmatchedBansNameWhatNoBuildOffers: an unknown name is accepted and made
// visible; a name some profile offers is matched even where this route's
// profile does not offer it.
func TestUnmatchedBansNameWhatNoBuildOffers(t *testing.T) {
	p := AlgorithmPolicy{Bans: allBans()}
	want := []string{"ciphers:arcfour", "key_exchanges:sntrup761x25519-sha512"}
	if got := p.UnmatchedBans(); !slices.Equal(got, want) {
		t.Errorf("UnmatchedBans() = %q, want %q", got, want)
	}
	if got := (AlgorithmPolicy{}).UnmatchedBans(); got != nil {
		t.Errorf("no bans reported %q unmatched", got)
	}
}

// TestTheDeclarationIsWhatIsOffered: the per-level declaration and the
// every-axis declaration are built from the expansion and say exactly what it
// offers — the per-level lists in their wire form.
func TestTheDeclarationIsWhatIsOffered(t *testing.T) {
	caps := AlgorithmFloorCapabilities()
	if len(caps) != len(AlgorithmFloors()) {
		t.Fatalf("declared %d levels, the build defines %d", len(caps), len(AlgorithmFloors()))
	}
	for i, c := range caps {
		if c.Level != AlgorithmFloors()[i] {
			t.Errorf("declaration %d is %q, want %q", i, c.Level, AlgorithmFloors()[i])
		}
		if want := (AlgorithmPolicy{Floor: c.Level}).WireKeyExchanges(); !slices.Equal(c.KeyExchanges, want) {
			t.Errorf("%s declares %q, the leg offers %q", c.Level, c.KeyExchanges, want)
		}
	}
	if got := caps[1].KeyExchanges; !slices.Equal(got, []string{KeyExchangeMLKEM768X25519}) {
		t.Errorf("pq-hybrid-kex declares %q", got)
	}

	offerable := OfferableAlgorithms()
	for _, p := range policies() {
		a := p.Algorithms()
		for _, axis := range []struct {
			name      string
			got, have []string
		}{
			{"key_exchanges", p.WireKeyExchanges(), offerable.KeyExchanges},
			{"ciphers", a.Ciphers, offerable.Ciphers},
			{"macs", a.MACs, offerable.MACs},
			{"host_keys", a.HostKeys, offerable.HostKeys},
			{"public_key_auth", a.PublicKeyAuths, offerable.PublicKeyAuths},
		} {
			for _, name := range axis.got {
				if !slices.Contains(axis.have, name) {
					t.Errorf("%s + %q offers %s %q, which the declaration omits", p.Profile, p.Floor, axis.name, name)
				}
			}
		}
	}
	if !slices.Contains(offerable.KeyExchanges, "curve25519-sha256@libssh.org") ||
		!slices.Contains(offerable.KeyExchanges, "diffie-hellman-group1-sha1") {
		t.Errorf("the declaration omits what the wire carries: %q", offerable.KeyExchanges)
	}
}

// TestFloorMetForEveryKindOfTarget is the target report's derivation, for a
// target offering ML-KEM, one offering only modern classical, one offering only
// sntrup761 plus classical, and one offering only SHA-1 — each on the success
// path (what it would negotiate) and the failure path (its whole list), and
// under a capped offer, which never reports above the cap it tested.
func TestFloorMetForEveryKindOfTarget(t *testing.T) {
	targets := []struct {
		name       string
		offers     []string
		negotiates map[AlgorithmFloor]string // by floor: what a success negotiates, "" when it fails
		floorMet   string
	}{
		{"ML-KEM", []string{"mlkem768x25519-sha256", "curve25519-sha256", "ecdh-sha2-nistp256"},
			map[AlgorithmFloor]string{"": "mlkem768x25519-sha256", AlgorithmFloorModernKEX: "mlkem768x25519-sha256", AlgorithmFloorPQHybridKEX: "mlkem768x25519-sha256"},
			"pq-hybrid-kex"},
		{"modern classical", []string{"curve25519-sha256", "ecdh-sha2-nistp256", "kex-strict-s-v00@openssh.com"},
			map[AlgorithmFloor]string{"": "curve25519-sha256", AlgorithmFloorModernKEX: "curve25519-sha256", AlgorithmFloorPQHybridKEX: ""},
			"modern-kex"},
		{"sntrup761 plus classical", []string{"sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com", "curve25519-sha256"},
			map[AlgorithmFloor]string{"": "curve25519-sha256", AlgorithmFloorModernKEX: "curve25519-sha256", AlgorithmFloorPQHybridKEX: ""},
			"modern-kex"},
		{"SHA-1 only", []string{"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"},
			map[AlgorithmFloor]string{"": "", AlgorithmFloorModernKEX: "", AlgorithmFloorPQHybridKEX: ""},
			"none"},
		{"libssh alias only", []string{"curve25519-sha256@libssh.org", "diffie-hellman-group14-sha1"},
			map[AlgorithmFloor]string{"": "curve25519-sha256@libssh.org", AlgorithmFloorModernKEX: "curve25519-sha256@libssh.org", AlgorithmFloorPQHybridKEX: ""},
			"modern-kex"},
	}
	for _, tgt := range targets {
		for _, floor := range []AlgorithmFloor{"", AlgorithmFloorModernKEX, AlgorithmFloorPQHybridKEX} {
			p := AlgorithmPolicy{Floor: floor}

			// What negotiation would pick: the client's first preference the
			// target offers — the rule the inference depends on.
			var negotiated string
			for _, kex := range p.WireKeyExchanges() {
				if slices.Contains(tgt.offers, kex) {
					negotiated = kex
					break
				}
			}
			if want := tgt.negotiates[floor]; negotiated != want {
				t.Fatalf("%s under %q negotiates %q, the table says %q", tgt.name, floor, negotiated, want)
			}

			if negotiated != "" {
				got, ok := p.FloorMet(negotiated, nil)
				if !ok {
					t.Errorf("%s under %q: a success was not an observation", tgt.name, floor)
				}
				if got != tgt.floorMet {
					t.Errorf("%s under %q: floor_met after a success = %q, want %q", tgt.name, floor, got, tgt.floorMet)
				}
				if floor != "" && AlgorithmFloor(got).Rank() < floor.Rank() {
					t.Errorf("%s under %q: a success under a floor reported below it (%q)", tgt.name, floor, got)
				}
			}
			// The failure path reads the target's whole list, whatever the
			// floor: it is exact.
			if got, ok := p.FloorMet("", tgt.offers); !ok || got != tgt.floorMet {
				t.Errorf("%s under %q: floor_met after a failure = %q (%v), want %q", tgt.name, floor, got, ok, tgt.floorMet)
			}
		}
	}

	// A success under an offer a ban reduced is not an observation; a failure
	// still is, because the target's list comes back whole.
	banned := AlgorithmPolicy{Bans: &AlgorithmBans{KeyExchanges: []string{KeyExchangeMLKEM768X25519}}}
	if _, ok := banned.FloorMet("curve25519-sha256", nil); ok {
		t.Error("a success under a key-exchange ban reported a floor_met")
	}
	if got, ok := banned.FloorMet("", []string{"mlkem768x25519-sha256"}); !ok || got != "pq-hybrid-kex" {
		t.Errorf("a failure under a key-exchange ban = %q (%v), want pq-hybrid-kex", got, ok)
	}
	// A ban on another axis is not a key-exchange ban.
	cipherBan := AlgorithmPolicy{Bans: &AlgorithmBans{Ciphers: []string{"aes128-ctr"}}}
	if got, ok := cipherBan.FloorMet("mlkem768x25519-sha256", nil); !ok || got != "pq-hybrid-kex" {
		t.Errorf("a cipher ban suppressed the key-exchange observation: %q (%v)", got, ok)
	}
	if _, ok := (AlgorithmPolicy{}).FloorMet("", nil); ok {
		t.Error("a handshake with nothing negotiated and no list reported a floor_met")
	}
}

// TestCauseNamesTheStepThatEmptiedTheAxis: the record says whether the fix is a
// profile, a floor, or a ban.
func TestCauseNamesTheStepThatEmptiedTheAxis(t *testing.T) {
	sha1Only := []string{"diffie-hellman-group14-sha1"}
	classical := []string{"curve25519-sha256", "ecdh-sha2-nistp256"}
	cases := []struct {
		name    string
		policy  AlgorithmPolicy
		axis    string
		offered []string
		want    AlgorithmPolicyCause
	}{
		{"profile", AlgorithmPolicy{}, AlgorithmAxisKeyExchange, sha1Only, AlgorithmPolicyCauseProfile},
		{"floor", AlgorithmPolicy{Floor: AlgorithmFloorPQHybridKEX}, AlgorithmAxisKeyExchange, classical, AlgorithmPolicyCauseFloor},
		{"floor, sntrup761", AlgorithmPolicy{Floor: AlgorithmFloorPQHybridKEX}, AlgorithmAxisKeyExchange,
			[]string{"sntrup761x25519-sha512", "curve25519-sha256"}, AlgorithmPolicyCauseFloor},
		{"ban", AlgorithmPolicy{Bans: &AlgorithmBans{Ciphers: []string{"aes128-ctr"}}}, AlgorithmAxisCipher,
			[]string{"aes128-ctr"}, AlgorithmPolicyCauseBan},
		{"ban on the alias", AlgorithmPolicy{Bans: &AlgorithmBans{KeyExchanges: []string{"curve25519-sha256"}}},
			AlgorithmAxisKeyExchange, []string{"curve25519-sha256@libssh.org"}, AlgorithmPolicyCauseBan},
		{"an axis no policy governs", AlgorithmPolicy{}, AlgorithmAxisCompression, []string{"zlib"}, AlgorithmPolicyCauseProfile},
	}
	for _, c := range cases {
		if got := c.policy.Cause(c.axis, c.offered); got != c.want {
			t.Errorf("%s: Cause = %q, want %q", c.name, got, c.want)
		}
	}
}

// validFloorResponse is a response the contract accepts, for the refusal tests
// to break one way at a time.
func validFloorResponse() *AuthorizeResponse {
	return &AuthorizeResponse{
		RouteType:         RouteTypeDirect,
		Target:            "host.company.com",
		PermittedChannels: []string{"session"},
		FilterPolicy:      FilterPolicy{Mode: FilterModeBlacklist},
		AlgorithmFloor:    AlgorithmFloorPQHybridKEX,
	}
}

// TestTheProfileFloorRuleIsAnAxis is Correction 3's table, and refusals are
// contract violations, never coercions.
func TestTheProfileFloorRuleIsAnAxis(t *testing.T) {
	for _, floor := range AlgorithmFloors() {
		for profile, refused := range map[AlgorithmProfile]bool{
			"":                            false,
			AlgorithmProfileDefault:       false,
			AlgorithmProfileLegacyRSASHA1: false, // signatures only — a different axis
			AlgorithmProfileLegacyDevice:  true,  // widens the very axis the floor narrows
		} {
			r := validFloorResponse()
			r.AlgorithmFloor, r.AlgorithmProfile = floor, profile
			err := r.Validate()
			if refused && err == nil {
				t.Errorf("%s + %s was accepted", profile, floor)
			}
			if !refused && err != nil {
				t.Errorf("%s + %s was refused: %v", profile, floor, err)
			}
		}
	}

	r := validFloorResponse()
	r.AlgorithmFloor = "pq-only-kex"
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "not a level this proxy enforces") {
		t.Errorf("an unknown floor was not refused: %v", err)
	}
	// And through the client's decoder: an unknown value is a protocol error,
	// never a response with no floor.
	var decoded AuthorizeResponse
	if err := json.Unmarshal([]byte(`{"route_type":"direct","target":"h","permitted_channels":[],"filter_policy":{"mode":"blacklist"},"algorithm_floor":"pq-only-kex"}`), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Validate() == nil {
		t.Error("an unknown floor decoded into a valid response")
	}
}

// TestBanRefusals: what is refused at authorize, and what is not.
func TestBanRefusals(t *testing.T) {
	refused := map[string]AuthorizeResponse{
		"a ban that empties an axis": {AlgorithmBans: &AlgorithmBans{Ciphers: AlgorithmProfileDefault.Algorithms().Ciphers}},
		"a ban that empties the floor's level": {AlgorithmFloor: AlgorithmFloorPQHybridKEX,
			AlgorithmBans: &AlgorithmBans{KeyExchanges: []string{KeyExchangeMLKEM768X25519}}},
		"an empty identifier": {AlgorithmBans: &AlgorithmBans{MACs: []string{""}}},
		"a duplicate":         {AlgorithmBans: &AlgorithmBans{HostKeys: []string{"ssh-rsa", "ssh-rsa"}}},
		"public-key auth emptied": {AlgorithmBans: &AlgorithmBans{
			PublicKeyAuths: AlgorithmProfileDefault.Algorithms().PublicKeyAuths}},
	}
	for name, overlay := range refused {
		r := validFloorResponse()
		r.AlgorithmFloor, r.AlgorithmBans = overlay.AlgorithmFloor, overlay.AlgorithmBans
		if err := r.Validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	accepted := map[string]AuthorizeResponse{
		"a name this build does not implement": {AlgorithmBans: &AlgorithmBans{KeyExchanges: []string{"sntrup761x25519-sha512"}}},
		"a name the route never offers":        {AlgorithmBans: &AlgorithmBans{KeyExchanges: []string{"diffie-hellman-group1-sha1"}}},
		"one of several under a floor": {AlgorithmFloor: AlgorithmFloorModernKEX,
			AlgorithmBans: &AlgorithmBans{KeyExchanges: []string{KeyExchangeMLKEM768X25519}}},
		"the same name on two axes": {AlgorithmBans: &AlgorithmBans{HostKeys: []string{"ssh-rsa"}, PublicKeyAuths: []string{"ssh-rsa"}}},
		"an empty object":           {AlgorithmBans: &AlgorithmBans{}},
	}
	for name, overlay := range accepted {
		r := validFloorResponse()
		r.AlgorithmFloor, r.AlgorithmBans = overlay.AlgorithmFloor, overlay.AlgorithmBans
		if err := r.Validate(); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
}

// TestTheFloorAndTheBansMovedTheVocabulary is this phase's version decision:
// both are fields on the strictly decoded response, so a proxy that does not
// know them must never be sent them — while what the proxy DECLARES on the
// request (the floor levels, the offerable algorithms) is outside the number.
func TestTheFloorAndTheBansMovedTheVocabulary(t *testing.T) {
	if PolicyVersion != 6 {
		t.Errorf("PolicyVersion = %d, want 6: algorithm_floor and algorithm_bans are vocabulary", PolicyVersion)
	}
	encoded, err := json.Marshal(&AuthorizeResponse{AlgorithmFloor: AlgorithmFloorModernKEX,
		AlgorithmBans: &AlgorithmBans{Ciphers: []string{"aes128-ctr"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"algorithm_floor":"modern-kex"`, `"algorithm_bans":{"ciphers":["aes128-ctr"]}`} {
		if !strings.Contains(string(encoded), field) {
			t.Errorf("the response does not carry %s: %s", field, encoded)
		}
	}
	for _, field := range []string{"algorithm_floors", `"algorithms"`, "floor_met"} {
		if strings.Contains(string(encoded), field) {
			t.Errorf("the response carries %s, which belongs to the request or the report", field)
		}
	}
	// Absent bans and no floor leave the response exactly as it was.
	plain, err := json.Marshal(&AuthorizeResponse{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "algorithm_floor") || strings.Contains(string(plain), "algorithm_bans") {
		t.Errorf("an unset floor or ban reached the wire: %s", plain)
	}
}

// TestADeclarationRoundTrips pins the capability shapes on the wire.
func TestADeclarationRoundTrips(t *testing.T) {
	offerable := OfferableAlgorithms()
	caps := &ProxyCapabilities{AlgorithmFloors: AlgorithmFloorCapabilities(), Algorithms: &offerable}
	encoded, err := json.Marshal(caps)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"algorithm_floors":[{"level":"modern-kex","key_exchanges":[`,
		`{"level":"pq-hybrid-kex","key_exchanges":["mlkem768x25519-sha256"]}`, `"algorithms":{"key_exchanges":[`,
		`"public_key_auth":[`} {
		if !strings.Contains(string(encoded), field) {
			t.Errorf("the declaration does not carry %s: %s", field, encoded)
		}
	}
	if !caps.DeclaresFloor(AlgorithmFloorPQHybridKEX) || !caps.DeclaresFloor("") ||
		(&ProxyCapabilities{}).DeclaresFloor(AlgorithmFloorModernKEX) || (*ProxyCapabilities)(nil).DeclaresFloor(AlgorithmFloorModernKEX) {
		t.Error("DeclaresFloor is wrong")
	}

	c := caps.Clone()
	c.AlgorithmFloors[0].KeyExchanges[0] = "mutated"
	c.Algorithms.Ciphers[0] = "mutated"
	if caps.AlgorithmFloors[0].KeyExchanges[0] == "mutated" || caps.Algorithms.Ciphers[0] == "mutated" {
		t.Error("ProxyCapabilities.Clone shares a slice")
	}

	report := &TargetCapabilities{Kex: &KexObservation{FloorMet: "modern-kex", Offered: []string{"curve25519-sha256"},
		ObservedAt: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}}
	encoded, err = json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &top); err != nil {
		t.Fatal(err)
	}
	for _, rungField := range []string{"observed_at", "execution", "reach", "detail"} {
		if _, present := top[rungField]; present {
			t.Errorf("a key-exchange-only report carries %q, a rung observation's field: %s", rungField, encoded)
		}
	}
	if report.CarriesRungs() || report.UndatedRungs() {
		t.Error("a key-exchange-only report reads as carrying rungs")
	}
	rc := report.Clone()
	rc.Kex.Offered[0] = "mutated"
	if report.Kex.Offered[0] == "mutated" {
		t.Error("TargetCapabilities.Clone shares the key-exchange observation")
	}
}

// TestAnUnreadableAlgorithmPolicyIsAProtocolError is the refusal as the proxy
// experiences it: through the REST client, the refused profile × floor pair, an
// unknown floor and a ban that empties an axis are each ErrProtocol — an
// outage, never a deny — and never a response with the restriction dropped.
func TestAnUnreadableAlgorithmPolicyIsAProtocolError(t *testing.T) {
	for name, body := range map[string]string{
		"legacy-device with a floor": `"algorithm_profile":"legacy-device","algorithm_floor":"modern-kex"`,
		"an unknown floor":           `"algorithm_floor":"pq-only-kex"`,
		"a ban that empties an axis": `"algorithm_bans":{"public_key_auth":["ssh-ed25519","sk-ssh-ed25519@openssh.com",` +
			`"sk-ecdsa-sha2-nistp256@openssh.com","ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521",` +
			`"rsa-sha2-256","rsa-sha2-512"]}`,
	} {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"route_type":"direct","target":"h","permitted_channels":["session"],`+
				`"filter_policy":{"mode":"blacklist"},`+body+`}`)
		})
		_, err := c.Authorize(context.Background(), &AuthorizeRequest{
			Identity: &Identity{Subject: "alice@example.com", Login: "alice"}, Target: "h", Conn: testConn()})
		if !errors.Is(err, ErrProtocol) || IsUnauthorized(err) {
			t.Errorf("%s: error = %v, want ErrProtocol and never a deny", name, err)
		}
	}
}

// TestCauseWhereNamesTheStepThatLeftTheKeyNothing: the public-key axis is
// attributed by whether the proxy's key had anything left to sign with.
func TestCauseWhereNamesTheStepThatLeftTheKeyNothing(t *testing.T) {
	signsWith := func(algo string) func(Algorithms) bool {
		return func(a Algorithms) bool { return slices.Contains(a.PublicKeyAuths, algo) }
	}
	if got := (AlgorithmPolicy{}).CauseWhere(signsWith("ssh-dss")); got != AlgorithmPolicyCauseProfile {
		t.Errorf("a key the profile never permits: %q, want profile", got)
	}
	banned := AlgorithmPolicy{Bans: &AlgorithmBans{PublicKeyAuths: []string{"ssh-ed25519"}}}
	if got := banned.CauseWhere(signsWith("ssh-ed25519")); got != AlgorithmPolicyCauseBan {
		t.Errorf("a key a ban left nothing: %q, want ban", got)
	}
	if got := (AlgorithmPolicy{}).CauseWhere(signsWith("ssh-ed25519")); got != AlgorithmPolicyCauseProfile {
		t.Errorf("a key every step permits, refused by the target: %q, want profile", got)
	}
}
