// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import "slices"

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
//
// Its wire keys are the five axis names phase 0045's AlgorithmBans and
// ProxyCapabilities.Algorithms carry, and that phase 0047's
// AlgorithmProfileCapability carries by embedding this type: those are the
// three places a list per axis travels, and they share this shape so an axis is
// spelled one way.
type Algorithms struct {
	// KeyExchanges are the key-exchange methods.
	KeyExchanges []string `json:"key_exchanges,omitempty"`
	// Ciphers apply in both directions.
	Ciphers []string `json:"ciphers,omitempty"`
	// MACs apply in both directions.
	MACs []string `json:"macs,omitempty"`
	// HostKeys are the host-key algorithms the target may present.
	HostKeys []string `json:"host_keys,omitempty"`
	// PublicKeyAuths are the signature algorithms the proxy may sign a
	// public-key authentication with. x/crypto has no client-side field for
	// this axis, so it is applied by restricting each signer.
	PublicKeyAuths []string `json:"public_key_auth,omitempty"`
}

// The negotiated axes, as the audit record names them (`algorithm_axis`, phase
// 0043). They are this repository's words rather than x/crypto's, because the
// library splits ciphers and MACs by direction and a route's policy does not —
// an operator needs to know WHICH list was short, not which way round the bytes
// were flowing. internal/auth/target maps the library's wording onto these.
const (
	AlgorithmAxisKeyExchange = "key_exchange"
	AlgorithmAxisHostKey     = "host_key"
	AlgorithmAxisCipher      = "cipher"
	AlgorithmAxisMAC         = "mac"
	AlgorithmAxisCompression = "compression"
	// AlgorithmAxisPublicKeyAuth is the proxy's own key finding no signature
	// algorithm the route permits and the target accepts (phase 0045). It is
	// not negotiated in KEXINIT, so the target's list is never known; what is
	// known is which step of the policy left the key nothing to sign with.
	AlgorithmAxisPublicKeyAuth = "public_key_auth"
)

// Axis returns the list a carries for one of the negotiated axes above, and
// whether the axis is one a route's policy governs at all. Compression is not:
// the proxy offers only "none", and no profile, floor or ban changes that.
func (a Algorithms) Axis(axis string) ([]string, bool) {
	switch axis {
	case AlgorithmAxisKeyExchange:
		return a.KeyExchanges, true
	case AlgorithmAxisHostKey:
		return a.HostKeys, true
	case AlgorithmAxisCipher:
		return a.Ciphers, true
	case AlgorithmAxisMAC:
		return a.MACs, true
	case AlgorithmAxisPublicKeyAuth:
		return a.PublicKeyAuths, true
	}
	return nil, false
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

// The key-exchange LEVELS of AlgorithmFloor (phase 0045), each defined by the
// set it accepts. The sets NEST — every exchange a level accepts is accepted by
// every level below it — and TestTheLadderIsADial fails the build for a level
// that breaks that.
//
// Each is its own pinned list rather than a reference to the default profile's,
// and on purpose. `default` FOLLOWS the library's secure classification (phase
// 0043), while modern-kex is defined by the contract as "no SHA-1 key
// exchange". Today the two lists are equal; if a library upgrade reclassifies
// something, the two pins fail separately and say which side moved.
var (
	// modernKeyExchanges is modern-kex's accepted set: every key exchange the
	// library implements except its SHA-1 ones, which is
	// ssh.SupportedAlgorithms().KeyExchanges at x/crypto v0.56.0
	// (TestModernKEXIsTheLibrarysSupportedSet), in the library's order.
	modernKeyExchanges = []string{
		KeyExchangeMLKEM768X25519,
		"curve25519-sha256",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
		"diffie-hellman-group14-sha256",
		"diffie-hellman-group16-sha512",
		"diffie-hellman-group-exchange-sha256",
	}
	// pqHybridKeyExchanges is pq-hybrid-kex's accepted set: the hybrid
	// post-quantum key exchanges this proxy IMPLEMENTS. x/crypto v0.56.0 has
	// ML-KEM-768 with X25519 and does not implement sntrup761x25519-sha512 at
	// all, so the set is that one exchange. When the library gains sntrup761
	// it goes here — the level's meaning is the property, not the list — and
	// that is a description change, not a vocabulary revision.
	pqHybridKeyExchanges = []string{KeyExchangeMLKEM768X25519}
)

// KeyExchangeMLKEM768X25519 is the hybrid post-quantum key exchange this proxy
// implements: ML-KEM-768 combined with X25519, spelled as SSH spells it. It is
// a string here so that this package stays free of x/crypto/ssh;
// TestTheHybridIsTheLibrarysMLKEM holds it equal to
// ssh.KeyExchangeMLKEM768X25519.
const KeyExchangeMLKEM768X25519 = "mlkem768x25519-sha256"

// KeyExchanges returns the set of key exchanges level f accepts IN THIS BUILD,
// highest level's members first, as the contract names them. No floor accepts
// no particular set, so it returns nil; an unknown level answers with the TOP
// level's set, because failing toward the narrowest set is the direction in
// which a programming error costs a connection rather than a weakening.
func (f AlgorithmFloor) KeyExchanges() []string {
	switch f.Rank() {
	case 0:
		return nil
	case 1:
		return cloneStrings(modernKeyExchanges)
	default:
		return cloneStrings(pqHybridKeyExchanges)
	}
}

// accepts reports whether level f accepts key exchange kex. It canonicalises the
// library's pre-standard alias first, so a target that negotiated
// curve25519-sha256@libssh.org is judged exactly as one that negotiated
// curve25519-sha256.
func (f AlgorithmFloor) accepts(kex string) bool {
	return slices.Contains(f.KeyExchanges(), canonicalKeyExchange(kex))
}

// KeyExchangeLevel is the HIGHEST level whose accepted set contains kex, or ""
// for a key exchange no level accepts (every SHA-1 one, and any name this build
// does not know).
func KeyExchangeLevel(kex string) AlgorithmFloor {
	var best AlgorithmFloor
	for _, level := range AlgorithmFloors() {
		if level.accepts(kex) {
			best = level
		}
	}
	return best
}

// The library's pre-standard spelling of curve25519-sha256, which it OFFERS ON
// THE WIRE immediately after curve25519-sha256 whenever that is configured and
// this is not (ssh.Config.SetDefaults, for OpenSSH 7.2 and earlier) — and which
// it cannot be told to leave out. The two names are one algorithm to this
// proxy: the alias belongs to every level curve25519-sha256 does, is declared
// wherever the proxy declares what it offers, and a ban on either name removes
// both, because removing curve25519-sha256 is the only way to stop the library
// from offering the alias. TestTheWireModelMatchesTheLibrary holds the model
// below to what the library actually does.
const (
	kexCurve25519       = "curve25519-sha256"
	kexCurve25519LibSSH = "curve25519-sha256@libssh.org"
)

func canonicalKeyExchange(kex string) string {
	if kex == kexCurve25519LibSSH {
		return kexCurve25519
	}
	return kex
}

// wireKeyExchanges is list exactly as the library puts it in KEXINIT.
func wireKeyExchanges(list []string) []string {
	if !slices.Contains(list, kexCurve25519) || slices.Contains(list, kexCurve25519LibSSH) {
		return cloneStrings(list)
	}
	out := make([]string, 0, len(list)+1)
	for _, kex := range list {
		out = append(out, kex)
		if kex == kexCurve25519 {
			out = append(out, kexCurve25519LibSSH)
		}
	}
	return out
}

// orderByLevel is the ordering rule every key-exchange offer obeys, floor or no
// floor, legacy-device's SHA-1 additions included: HIGHEST LEVEL FIRST, and the
// order within a level left as it was. SSH negotiation picks the client's first
// preference the server also offers, so an offer in this order makes the
// exchange that gets negotiated name the highest level the target meets among
// those offered — which is the inference the target report (FloorMet) rests on.
func orderByLevel(kex []string) []string {
	out := cloneStrings(kex)
	slices.SortStableFunc(out, func(a, b string) int {
		return KeyExchangeLevel(b).Rank() - KeyExchangeLevel(a).Rank()
	})
	return out
}

// AlgorithmPolicy is everything a route says about the algorithms of its
// proxy→target leg: the profile (phase 0043), the floor and the bans (phase
// 0045). It is a value, carried beside the expanded lists wherever they go, so
// the records can name the policy IN FORCE and a failure can say which part of
// it the target could not meet.
type AlgorithmPolicy struct {
	// Profile is the preset; empty means AlgorithmProfileDefault.
	Profile AlgorithmProfile
	// Floor is the minimum key-exchange level; empty means no floor.
	Floor AlgorithmFloor
	// Bans are what the leg must never offer; nil means nothing is banned.
	Bans *AlgorithmBans
}

// Clone returns a copy that shares no slice with p.
func (p AlgorithmPolicy) Clone() AlgorithmPolicy {
	p.Bans = p.Bans.Clone()
	return p
}

// Algorithms expands the policy into the lists a connection offers. It is the
// ONE place a proxy→target connection's lists come from — phase 0043's
// expansion, which this extends rather than duplicates — and it computes them
// in a fixed order:
//
//  1. the PROFILE's expansion (AlgorithmProfile.Algorithms), with the key
//     exchanges ordered highest level first (orderByLevel);
//  2. the FLOOR narrows the key exchanges to what its level accepts. It is an
//     intersection, never a replacement: a floor can only remove, so a future
//     profile narrower than the level is narrowed further rather than widened
//     back. Every other axis is the profile's answer, unchanged;
//  3. every BANNED identifier is removed, last, so a ban always wins —
//     including over what legacy-device adds — and is subtracted from what the
//     route would otherwise have offered, never from the library's "supported"
//     set, which would make a ban ADD algorithms the route never offered.
//
// An axis a ban leaves empty is refused by Validate before anything dials, so
// the result always has a list on every axis the applier would otherwise fill
// with defaults.
func (p AlgorithmPolicy) Algorithms() Algorithms {
	_, _, final := p.stages()
	return final
}

// stages returns the lists after each step of Algorithms' expansion: the
// profile's, then narrowed by the floor, then with every ban removed. The
// intermediate two are what attribute a failure to a step (Cause) and tell
// whether a ban reduced an offer (FloorMet).
func (p AlgorithmPolicy) stages() (profile, floored, final Algorithms) {
	profile = p.Profile.Resolve().Algorithms()
	profile.KeyExchanges = orderByLevel(profile.KeyExchanges)

	floored = profile.Clone()
	if p.Floor != "" {
		floored.KeyExchanges = slices.DeleteFunc(floored.KeyExchanges, func(kex string) bool {
			return !p.Floor.accepts(kex)
		})
	}

	final = floored.Clone()
	if b := p.Bans; b != nil {
		final.KeyExchanges = withoutBannedKeyExchanges(final.KeyExchanges, b.KeyExchanges)
		final.Ciphers = without(final.Ciphers, b.Ciphers)
		final.MACs = without(final.MACs, b.MACs)
		final.HostKeys = without(final.HostKeys, b.HostKeys)
		final.PublicKeyAuths = without(final.PublicKeyAuths, b.PublicKeyAuths)
	}
	return profile, floored, final
}

// without returns list minus every name in banned, order kept.
func without(list, banned []string) []string {
	return slices.DeleteFunc(cloneStrings(list), func(name string) bool {
		return slices.Contains(banned, name)
	})
}

// withoutBannedKeyExchanges is without for the key-exchange axis, where a ban
// on either spelling of curve25519 removes both (see kexCurve25519LibSSH).
func withoutBannedKeyExchanges(list, banned []string) []string {
	canonical := make([]string, len(banned))
	for i, name := range banned {
		canonical[i] = canonicalKeyExchange(name)
	}
	return slices.DeleteFunc(cloneStrings(list), func(kex string) bool {
		return slices.Contains(canonical, canonicalKeyExchange(kex))
	})
}

// WireKeyExchanges is the key-exchange list a connection under this policy
// actually puts on the wire, the library's alias included. It is what a
// capability declaration and a comparison with a TARGET's list must use; the
// configured list (Algorithms().KeyExchanges) is what the applier hands the
// library.
func (p AlgorithmPolicy) WireKeyExchanges() []string {
	return wireKeyExchanges(p.Algorithms().KeyExchanges)
}

// KeyExchangeBanned reports whether a ban REDUCED this policy's key-exchange
// offer — as distinct from a ban naming something the route never offered,
// which changes nothing on the wire.
//
// It matters to the target report and nowhere else: a handshake whose offer a
// ban reduced cannot say what the target WOULD have picked, so it is not an
// observation of the target's level (FloorMet).
func (p AlgorithmPolicy) KeyExchangeBanned() bool {
	_, floored, final := p.stages()
	return len(final.KeyExchanges) != len(floored.KeyExchanges)
}

// AlgorithmPolicyCause is WHICH step of the expansion left an axis with nothing
// the target offered (phase 0045): the attribute `algorithm_policy_cause` on a
// `target.algorithm_policy_unmet` record. The fix differs by cause — a legacy
// profile, a lower floor, or a lifted ban — and so the record says which.
type AlgorithmPolicyCause string

const (
	// AlgorithmPolicyCauseProfile is a target the profile alone could not
	// meet (phase 0043's case): the route needs a different profile.
	AlgorithmPolicyCauseProfile AlgorithmPolicyCause = "profile"
	// AlgorithmPolicyCauseFloor is a target the profile could meet and the
	// floor then excluded: the target does not reach the route's level.
	AlgorithmPolicyCauseFloor AlgorithmPolicyCause = "floor"
	// AlgorithmPolicyCauseBan is a target that offered only algorithms a ban
	// removed.
	AlgorithmPolicyCauseBan AlgorithmPolicyCause = "ban"
)

// Cause decides which step of the expansion removed the last algorithm the
// target offered on axis — the first step after which nothing on the proxy's
// list was on the target's. It compares WIRE lists, the library's alias
// included, because that is what the target was actually offered. An axis the
// policy does not govern, or one where every step still overlapped the target
// (which a real negotiation failure never produces), is the profile's.
func (p AlgorithmPolicy) Cause(axis string, offered []string) AlgorithmPolicyCause {
	profile, floored, final := p.stages()
	for _, step := range []struct {
		lists Algorithms
		cause AlgorithmPolicyCause
	}{
		{profile, AlgorithmPolicyCauseProfile},
		{floored, AlgorithmPolicyCauseFloor},
		{final, AlgorithmPolicyCauseBan},
	} {
		list, governed := step.lists.Axis(axis)
		if !governed {
			return AlgorithmPolicyCauseProfile
		}
		if axis == AlgorithmAxisKeyExchange {
			list = wireKeyExchanges(list)
		}
		if !overlaps(list, offered) {
			return step.cause
		}
	}
	return AlgorithmPolicyCauseProfile
}

// CauseWhere is Cause for a question the target's list cannot answer: it
// names the first step of the expansion after which permits(lists) no longer
// holds, and the profile when every step still holds — which is the target
// refusing everything the route permitted. It is how a public-key failure is
// attributed, where the question is whether the proxy's own key had anything
// left to sign with.
func (p AlgorithmPolicy) CauseWhere(permits func(Algorithms) bool) AlgorithmPolicyCause {
	profile, floored, final := p.stages()
	switch {
	case !permits(profile):
		return AlgorithmPolicyCauseProfile
	case !permits(floored):
		return AlgorithmPolicyCauseFloor
	case !permits(final):
		return AlgorithmPolicyCauseBan
	}
	return AlgorithmPolicyCauseProfile
}

func overlaps(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

// UnmatchedBans lists the banned names that match nothing THIS BUILD could
// offer on their axis, under any profile or floor level, as "axis:name" in the
// contract's axis spelling (key_exchanges:…), sorted.
//
// Such a ban is not refused. Banning something the proxy never offers is
// already satisfied, and refusing it would turn a same-day ban issued after an
// advisory into an outage on every build that never had the algorithm. What it
// must not be is SILENT, because a typo in a ban looks exactly like a working
// ban: this is what the record's `algorithm_bans_unmatched` carries.
func (p AlgorithmPolicy) UnmatchedBans() []string {
	if p.Bans == nil {
		return nil
	}
	offerable := OfferableAlgorithms()
	var out []string
	for _, axis := range BanAxes(*p.Bans) {
		can := axis.list(offerable)
		for _, name := range axis.Names {
			if !slices.Contains(can, name) {
				out = append(out, axis.Name+":"+name)
			}
		}
	}
	slices.Sort(out)
	return out
}

// BanAxis is one axis of an AlgorithmBans, spelled as the contract spells it —
// which is also the suffix of the record's `algorithm_bans.<axis>` attribute.
type BanAxis struct {
	// Name is the wire key: key_exchanges, ciphers, macs, host_keys or
	// public_key_auth.
	Name string
	// Names are the banned identifiers on it, as the route listed them.
	Names []string
	list  func(Algorithms) []string
}

// BanAxes returns b's five axes in the contract's order, empty ones included,
// so a caller iterating them cannot forget one.
func BanAxes(b AlgorithmBans) []BanAxis {
	return []BanAxis{
		{Name: "key_exchanges", Names: b.KeyExchanges, list: func(a Algorithms) []string { return a.KeyExchanges }},
		{Name: "ciphers", Names: b.Ciphers, list: func(a Algorithms) []string { return a.Ciphers }},
		{Name: "macs", Names: b.MACs, list: func(a Algorithms) []string { return a.MACs }},
		{Name: "host_keys", Names: b.HostKeys, list: func(a Algorithms) []string { return a.HostKeys }},
		{Name: "public_key_auth", Names: b.PublicKeyAuths, list: func(a Algorithms) []string { return a.PublicKeyAuths }},
	}
}

// Clone deep-copies the bans.
func (b *AlgorithmBans) Clone() *AlgorithmBans {
	if b == nil {
		return nil
	}
	out := AlgorithmBans(Algorithms(*b).Clone())
	return &out
}

// IsZero reports whether nothing is banned, which is what an absent object
// means too.
func (b *AlgorithmBans) IsZero() bool { return b == nil || Algorithms(*b).IsZero() }

// OfferableAlgorithms is every identifier this build can put in an offer, per
// axis, under ANY profile and ANY floor level: the union of Algorithms over
// every such policy, key exchanges in their wire form (the library's alias
// included). It is built from the same function every connection dials with,
// so it cannot describe anything the proxy does not offer — it is the
// declaration `ProxyCapabilities.algorithms` carries, and what a ban is judged
// "unmatched" against.
func OfferableAlgorithms() Algorithms {
	var out Algorithms
	floors := append([]AlgorithmFloor{""}, AlgorithmFloors()...)
	for _, profile := range AlgorithmProfiles() {
		for _, floor := range floors {
			policy := AlgorithmPolicy{Profile: profile, Floor: floor}
			a := policy.Algorithms()
			out.KeyExchanges = union(out.KeyExchanges, policy.WireKeyExchanges())
			out.Ciphers = union(out.Ciphers, a.Ciphers)
			out.MACs = union(out.MACs, a.MACs)
			out.HostKeys = union(out.HostKeys, a.HostKeys)
			out.PublicKeyAuths = union(out.PublicKeyAuths, a.PublicKeyAuths)
		}
	}
	return out
}

// union appends the names of more that base does not have, in order.
func union(base, more []string) []string {
	for _, name := range more {
		if !slices.Contains(base, name) {
			base = append(base, name)
		}
	}
	return base
}

// AlgorithmFloorCapabilities is the per-level half of this build's declaration
// (`ProxyCapabilities.algorithm_floors`): every level it enforces, with the key
// exchanges that level accepts IN THIS BUILD, in the wire form the leg offers.
// It is built from Algorithms — the function every connection dials with — so
// it cannot declare anything other than what the proxy offers under that
// floor. A level's members can change with a release (sntrup761 arriving is
// exactly that); declaring them per build is what lets a fleet view show it
// during a rolling upgrade rather than hide it.
func AlgorithmFloorCapabilities() []AlgorithmFloorCapability {
	levels := AlgorithmFloors()
	out := make([]AlgorithmFloorCapability, 0, len(levels))
	for _, level := range levels {
		out = append(out, AlgorithmFloorCapability{
			Level:        level,
			KeyExchanges: AlgorithmPolicy{Floor: level}.WireKeyExchanges(),
		})
	}
	return out
}

// AlgorithmProfileCapabilities is the per-profile half of this build's
// declaration (`ProxyCapabilities.algorithm_profiles`, phase 0047): every
// profile it accepts, in AlgorithmProfiles' order, with what that profile offers
// on each axis before any floor narrows it or any ban subtracts from it — the
// profile stage of the expansion, key exchanges in the wire form the leg offers.
// It is built from Algorithms — the function every connection dials with — so
// it cannot declare anything other than what the proxy offers under that
// profile. Nothing in it is written out by hand: a copy of the lists drifts
// from the expansion the first time either changes, which is the failure the
// declaration exists to prevent, whether the copy is here or in Hoplock
// Control.
//
// With AlgorithmFloorCapabilities it is enough to reproduce Validate's refusal
// of a ban that leaves an axis nothing to offer, from the wire alone, by the
// rule api/README.md states; TestTheDeclarationIsEnoughToJudgeEveryBan holds
// the two to agreement.
func AlgorithmProfileCapabilities() []AlgorithmProfileCapability {
	profiles := AlgorithmProfiles()
	out := make([]AlgorithmProfileCapability, 0, len(profiles))
	for _, profile := range profiles {
		policy := AlgorithmPolicy{Profile: profile}
		offered := policy.Algorithms()
		offered.KeyExchanges = policy.WireKeyExchanges()
		out = append(out, AlgorithmProfileCapability{Profile: profile, Algorithms: offered})
	}
	return out
}

// KexFloorNone is the target report's floor_met for a target observed to meet
// no level at all — one whose only key exchanges are SHA-1 ones.
const KexFloorNone = "none"

// FloorMet derives the HIGHEST level a target was observed to meet, from one
// handshake under this policy — the target report's `floor_met` (phase 0045).
// It is the one place the rule lives, and it has two inputs because a handshake
// tells the proxy one of two things:
//
//   - after a FAILED key-exchange negotiation, targetOffered is the target's
//     whole list (the library returns it in the error), and the answer is
//     exact: the highest level any offered exchange belongs to;
//   - after a SUCCESS, only the negotiated exchange is known, and the answer
//     is the highest level containing it. That is sound only because every
//     offer is ordered highest level first (orderByLevel): a target that
//     negotiated a classical exchange was offered every hybrid first and has
//     none of them. Under a floor the offer is the floor's accepted set, which
//     by nesting still contains every higher level's members, so a success
//     proves at least the floor and never claims a level that was not tested.
//
// ok is false when the handshake is NOT an observation of the target: a success
// under an offer a ban reduced cannot say what the target would have picked,
// and neither input may be missing. targetOffered is used only when non-nil.
func (p AlgorithmPolicy) FloorMet(negotiated string, targetOffered []string) (floorMet string, ok bool) {
	if targetOffered != nil {
		best := AlgorithmFloor("")
		for _, kex := range targetOffered {
			if level := KeyExchangeLevel(kex); level.Rank() > best.Rank() {
				best = level
			}
		}
		return floorName(best), true
	}
	if negotiated == "" || p.KeyExchangeBanned() {
		return "", false
	}
	return floorName(KeyExchangeLevel(negotiated)), true
}

func floorName(level AlgorithmFloor) string {
	if level == "" {
		return KexFloorNone
	}
	return string(level)
}

// ProfileWidensKeyExchange reports whether profile p adds key exchanges beyond
// the default profile's — the AXIS a floor narrows. It is the whole of the
// profile × floor rule: such a profile describes, with any floor, a leg that
// adds exactly what the floor forbids, and the pair is refused. It is written as
// the axis rather than as a list of profile names so that the next profile added
// is placed by rule rather than by analogy — legacy-rsa-sha1 changes only
// signatures and is accepted with a floor; legacy-device adds the SHA-1 key
// exchanges and is not.
func ProfileWidensKeyExchange(p AlgorithmProfile) bool {
	def := AlgorithmProfileDefault.Algorithms().KeyExchanges
	for _, kex := range p.Resolve().Algorithms().KeyExchanges {
		if !slices.Contains(def, kex) {
			return true
		}
	}
	return false
}
