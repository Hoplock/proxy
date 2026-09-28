// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// This file is phase 0047: the per-profile declaration, and the proof that what
// a proxy declares on the wire is enough for a server to refuse exactly the bans
// the proxy refuses. The judgement below plays Hoplock Control. It reads the
// declaration only as JSON, never through this package's types, so it can pass
// only if the wire carries enough.

// wireAxes are the five axes as the contract spells them, in the order Validate
// checks them. They are written out rather than taken from BanAxes so that the
// reference judgement shares nothing with the code it judges.
var wireAxes = []string{"key_exchanges", "ciphers", "macs", "host_keys", "public_key_auth"}

// wireDeclaration is a proxy's declaration as a server holds it.
type wireDeclaration struct {
	// floors maps a level to the key exchanges it accepts in that build.
	floors map[string][]string
	// profiles maps a profile to what it offers, per axis, before any floor or
	// ban.
	profiles map[string]map[string][]string
	// algorithms is the build-wide union, per axis.
	algorithms map[string][]string
}

// decodeDeclaration marshals caps as the proxy sends them and decodes the JSON
// into plain maps keyed by the contract's spelling.
func decodeDeclaration(t *testing.T, caps *ProxyCapabilities) wireDeclaration {
	t.Helper()
	raw, err := json.Marshal(caps)
	if err != nil {
		t.Fatalf("marshal the declaration: %v", err)
	}
	var doc struct {
		AlgorithmFloors []struct {
			Level        string   `json:"level"`
			KeyExchanges []string `json:"key_exchanges"`
		} `json:"algorithm_floors"`
		AlgorithmProfiles []map[string]json.RawMessage `json:"algorithm_profiles"`
		Algorithms        map[string][]string          `json:"algorithms"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode the declaration %s: %v", raw, err)
	}
	d := wireDeclaration{
		floors:     map[string][]string{},
		profiles:   map[string]map[string][]string{},
		algorithms: doc.Algorithms,
	}
	for _, f := range doc.AlgorithmFloors {
		d.floors[f.Level] = f.KeyExchanges
	}
	for _, entry := range doc.AlgorithmProfiles {
		var name string
		if err := json.Unmarshal(entry["profile"], &name); err != nil {
			t.Fatalf("a declared profile has no name: %v", err)
		}
		axes := map[string][]string{}
		for _, axis := range wireAxes {
			var list []string
			if err := json.Unmarshal(entry[axis], &list); err != nil {
				t.Fatalf("%s declares %s unreadably: %v", name, axis, err)
			}
			axes[axis] = list
		}
		d.profiles[name] = axes
	}
	return d
}

// judge is the reference judgement: the composition rule api/README.md states,
// applied to the wire declaration and to the bans as a server authored them.
// It returns the first axis, in the contract's order, that the bans leave
// nothing to offer, or "" when every axis keeps something. ok is false when the
// declaration does not cover the route, which a server must treat as unknown.
//
// oneExchange is step 3's curve25519 rule. It is a parameter only so that a
// test can show the matrix contains a case plain subtraction gets wrong.
func (d wireDeclaration) judge(profile, floor string, bans map[string][]string, oneExchange bool) (emptied string, ok bool) {
	if profile == "" {
		profile = "default" // the contract's absent-value default
	}
	offer, declared := d.profiles[profile]
	if !declared {
		return "", false
	}
	var level []string
	if floor != "" {
		if level, declared = d.floors[floor]; !declared {
			return "", false
		}
	}
	for _, axis := range wireAxes {
		// 1. Start from the profile's list.
		left := slices.Clone(offer[axis])
		// 2. Under a floor, intersect key exchanges with the level's list.
		if axis == "key_exchanges" && floor != "" {
			left = slices.DeleteFunc(left, func(name string) bool { return !slices.Contains(level, name) })
		}
		// 3. Subtract the bans, the two curve25519 spellings as one exchange.
		banned := bans[axis]
		if axis == "key_exchanges" && oneExchange {
			banned = withBothCurve25519Spellings(banned)
		}
		left = slices.DeleteFunc(left, func(name string) bool { return slices.Contains(banned, name) })
		if len(left) == 0 {
			return axis, true
		}
	}
	return "", true
}

// withBothCurve25519Spellings is step 3's rule as a server writes it: a ban
// naming either spelling of curve25519 bans both.
func withBothCurve25519Spellings(banned []string) []string {
	spellings := []string{"curve25519-sha256", "curve25519-sha256@libssh.org"}
	for _, name := range spellings {
		if slices.Contains(banned, name) {
			return append(slices.Clone(banned), spellings...)
		}
	}
	return banned
}

// validateEmptied is the proxy's side of the comparison: the axis Validate says
// the bans leave nothing to offer, or "" when it accepts the route. A refusal
// for any other reason fails the test, because the case was built wrongly and
// proves nothing.
func validateEmptied(t *testing.T, name string, p AlgorithmPolicy) string {
	t.Helper()
	r := &AuthorizeResponse{
		RouteType:         RouteTypeDirect,
		Target:            "host.company.com",
		PermittedChannels: []string{"session"},
		FilterPolicy:      FilterPolicy{Mode: FilterModeBlacklist},
		AlgorithmProfile:  p.Profile,
		AlgorithmFloor:    p.Floor,
		AlgorithmBans:     p.Bans,
	}
	err := r.Validate()
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no key exchange to offer"):
		return "key_exchanges"
	case strings.HasPrefix(msg, "algorithm_bans.") &&
		(strings.Contains(msg, "leaves the route nothing to offer") || strings.Contains(msg, "removes every key exchange")):
		axis, _, _ := strings.Cut(strings.TrimPrefix(msg, "algorithm_bans."), " ")
		return axis
	}
	t.Fatalf("%s: Validate refused for a reason other than an emptied axis: %v", name, err)
	return ""
}

// wireBans is bans as the server that authored them holds them: the JSON it
// sends, keyed by the contract's spelling.
func wireBans(t *testing.T, bans *AlgorithmBans) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	if bans == nil {
		return out
	}
	raw, err := json.Marshal(bans)
	if err != nil {
		t.Fatalf("marshal the bans: %v", err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode the bans %s: %v", raw, err)
	}
	return out
}

// thisBuildsDeclaration is the algorithm half of what this build sends on every
// authorize request (internal/auth/target.ProxyCapabilities).
func thisBuildsDeclaration() *ProxyCapabilities {
	offerable := OfferableAlgorithms()
	return &ProxyCapabilities{
		AlgorithmFloors:   AlgorithmFloorCapabilities(),
		AlgorithmProfiles: AlgorithmProfileCapabilities(),
		Algorithms:        &offerable,
	}
}

// TestTheProfileDeclarationIsTheExpansion: one entry per profile, in
// AlgorithmProfiles' order, each exactly what the leg offers under that profile
// with no floor and no ban, key exchanges in their wire form.
func TestTheProfileDeclarationIsTheExpansion(t *testing.T) {
	got := AlgorithmProfileCapabilities()
	if len(got) != len(AlgorithmProfiles()) {
		t.Fatalf("declared %d profiles, the contract defines %d", len(got), len(AlgorithmProfiles()))
	}
	for i, entry := range got {
		profile := AlgorithmProfiles()[i]
		if entry.Profile != profile {
			t.Errorf("declaration %d is %q, want %q", i, entry.Profile, profile)
		}
		policy := AlgorithmPolicy{Profile: profile}
		want := policy.Algorithms()
		want.KeyExchanges = policy.WireKeyExchanges()
		if !reflect.DeepEqual(entry.Algorithms, want) {
			t.Errorf("%s declares %+v, the leg offers %+v", profile, entry.Algorithms, want)
		}
		// Alias-complete, as algorithm_floors is: the library offers the libssh
		// spelling wherever it offers curve25519-sha256, so the declaration does.
		if !slices.Contains(entry.KeyExchanges, kexCurve25519) || !slices.Contains(entry.KeyExchanges, kexCurve25519LibSSH) {
			t.Errorf("%s declares key exchanges %q without both curve25519 spellings", profile, entry.KeyExchanges)
		}
	}

	// Before any floor: default still declares its classical exchanges, which
	// pq-hybrid-kex would remove, and legacy-device its SHA-1 ones, which any
	// floor would.
	if !slices.Contains(got[0].KeyExchanges, "ecdh-sha2-nistp256") {
		t.Errorf("default declares %q: narrowed by a floor", got[0].KeyExchanges)
	}
	if legacy := got[len(got)-1]; legacy.Profile != AlgorithmProfileLegacyDevice || !slices.Contains(legacy.KeyExchanges, "diffie-hellman-group1-sha1") {
		t.Errorf("the last declaration is %q with key exchanges %q, want legacy-device with its SHA-1 exchanges", legacy.Profile, legacy.KeyExchanges)
	}
}

// TestEveryDeclaredProfileCarriesEveryAxis is the invariant the contract's
// `required` rests on. Algorithms' fields are omitempty, so an axis a profile
// left empty would vanish from the wire and a server reading the schema would
// be handed an entry it was promised could not exist. So every entry marshals
// with exactly `profile` and the five axes, each a non-empty list.
func TestEveryDeclaredProfileCarriesEveryAxis(t *testing.T) {
	for _, entry := range AlgorithmProfileCapabilities() {
		raw, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("marshal %s: %v", entry.Profile, err)
		}
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(raw, &keys); err != nil {
			t.Fatalf("decode %s: %v", raw, err)
		}
		want := append([]string{"profile"}, wireAxes...)
		got := make([]string, 0, len(keys))
		for key := range keys {
			got = append(got, key)
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s travels as %q, want exactly %q: %s", entry.Profile, got, want, raw)
		}
		for _, axis := range wireAxes {
			var list []string
			if err := json.Unmarshal(keys[axis], &list); err != nil || len(list) == 0 {
				t.Errorf("%s declares %s as %s: every axis must be a non-empty list", entry.Profile, axis, keys[axis])
			}
		}
	}
}

// TestAlgorithmsIsTheUnionOfTheProfiles: `algorithms` stays what it was, and it
// is the union of the per-profile lists on every axis, as sets. That holds
// because a floor only narrows. A level, or an expansion, that let a floor add
// an identifier no profile offers fails here rather than quietly making the two
// declarations disagree.
func TestAlgorithmsIsTheUnionOfTheProfiles(t *testing.T) {
	d := decodeDeclaration(t, thisBuildsDeclaration())
	for _, axis := range wireAxes {
		var union []string
		for _, offer := range d.profiles {
			union = append(union, offer[axis]...)
		}
		if got, want := asSet(d.algorithms[axis]), asSet(union); !slices.Equal(got, want) {
			t.Errorf("algorithms.%s = %q, the union of algorithm_profiles is %q", axis, got, want)
		}
	}
}

func asSet(list []string) []string {
	out := slices.Clone(list)
	slices.Sort(out)
	return slices.Compact(out)
}

// banCase is one route to judge: a policy, and a name that says what its bans
// remove.
type banCase struct {
	name   string
	policy AlgorithmPolicy
}

// unofferedNames are identifiers no profile or level of this build offers, one
// per axis. public_key_auth's is a name the build does offer on another axis.
var unofferedNames = map[string]string{
	"key_exchanges":   "sntrup761x25519-sha512",
	"ciphers":         "arcfour",
	"macs":            "hmac-md5",
	"host_keys":       "ssh-xmss@openssh.com",
	"public_key_auth": "ssh-dss",
}

// bansOn is a ban on one axis, spelled as the contract spells it.
func bansOn(axis string, names []string) *AlgorithmBans {
	names = slices.Clone(names)
	switch axis {
	case "key_exchanges":
		return &AlgorithmBans{KeyExchanges: names}
	case "ciphers":
		return &AlgorithmBans{Ciphers: names}
	case "macs":
		return &AlgorithmBans{MACs: names}
	case "host_keys":
		return &AlgorithmBans{HostKeys: names}
	case "public_key_auth":
		return &AlgorithmBans{PublicKeyAuths: names}
	}
	panic("unknown axis " + axis)
}

// banCases is the matrix for one accepted profile and floor. On each axis in
// turn the bans remove everything the route offers; everything but one name,
// for each name; one name, for each name; and a name no build offers. On the key
// exchanges they also name each curve25519 spelling alone, both together, and
// every other exchange plus one spelling, which is the case plain subtraction
// gets wrong. Two cases ban on several axes at once. The offer is generated
// from the build, which is fine: only the judgement is held to the wire.
func banCases(p AlgorithmPolicy) []banCase {
	offered := p.Algorithms()
	offered.KeyExchanges = p.WireKeyExchanges()
	lists := map[string][]string{
		"key_exchanges":   offered.KeyExchanges,
		"ciphers":         offered.Ciphers,
		"macs":            offered.MACs,
		"host_keys":       offered.HostKeys,
		"public_key_auth": offered.PublicKeyAuths,
	}
	route := string(p.Profile.Resolve())
	if p.Floor != "" {
		route += " + " + string(p.Floor)
	}
	var cases []banCase
	add := func(what string, bans *AlgorithmBans) {
		policy := p
		policy.Bans = bans
		cases = append(cases, banCase{name: route + ", " + what, policy: policy})
	}
	for _, axis := range wireAxes {
		list := lists[axis]
		add(axis+": everything", bansOn(axis, list))
		for _, keep := range list {
			add(axis+": everything but "+keep, bansOn(axis, slices.DeleteFunc(slices.Clone(list), func(n string) bool { return n == keep })))
			add(axis+": only "+keep, bansOn(axis, []string{keep}))
		}
		add(axis+": a name no build offers", bansOn(axis, []string{unofferedNames[axis]}))
	}

	spellings := []string{kexCurve25519, kexCurve25519LibSSH}
	others := slices.DeleteFunc(slices.Clone(lists["key_exchanges"]), func(n string) bool { return slices.Contains(spellings, n) })
	for _, spelling := range spellings {
		add("key_exchanges: "+spelling+" alone", bansOn("key_exchanges", []string{spelling}))
		add("key_exchanges: every other exchange plus "+spelling, bansOn("key_exchanges", append(slices.Clone(others), spelling)))
	}
	add("key_exchanges: both curve25519 spellings", bansOn("key_exchanges", spellings))

	add("every axis at once", allBans())
	add("ciphers and macs both emptied", &AlgorithmBans{Ciphers: slices.Clone(offered.Ciphers), MACs: slices.Clone(offered.MACs)})
	return cases
}

// TestTheDeclarationIsEnoughToJudgeEveryBan is the test that proves the request
// is met. For every profile and floor the contract accepts, the absent profile
// included, and for every ban in the matrix, a judgement made from the wire
// declaration alone, by the rule api/README.md states, agrees with Validate:
// the same routes refused, on the same axis. If the two ever disagree, the
// declaration is not enough, and a server's check built on it would refuse more
// or less than the proxy does.
func TestTheDeclarationIsEnoughToJudgeEveryBan(t *testing.T) {
	d := decodeDeclaration(t, thisBuildsDeclaration())
	for axis, name := range unofferedNames {
		if slices.Contains(d.algorithms[axis], name) {
			t.Fatalf("this build offers %s %q, which the matrix uses as a name no build offers", axis, name)
		}
	}

	routes := policies()
	for _, floor := range append([]AlgorithmFloor{""}, AlgorithmFloors()...) {
		routes = append(routes, AlgorithmPolicy{Floor: floor}) // no profile named
	}
	var judged, refused, plainGetsWrong int
	for _, route := range routes {
		for _, c := range banCases(route) {
			want := validateEmptied(t, c.name, c.policy)
			bans := wireBans(t, c.policy.Bans)
			got, ok := d.judge(string(c.policy.Profile), string(c.policy.Floor), bans, true)
			if !ok {
				t.Fatalf("%s: the declaration does not cover the route", c.name)
			}
			if got != want {
				t.Errorf("%s: Validate %s, the wire judgement %s", c.name, verdict(want), verdict(got))
			}
			if plain, _ := d.judge(string(c.policy.Profile), string(c.policy.Floor), bans, false); plain != want {
				plainGetsWrong++
			}
			judged++
			if want != "" {
				refused++
			}
		}
	}
	// A matrix that never refused, never accepted, or never needed step 3's
	// curve25519 rule would prove nothing about the part it skipped.
	if refused == 0 || refused == judged || plainGetsWrong == 0 {
		t.Errorf("the matrix judged %d routes, refused %d, and plain subtraction got %d wrong: it must exercise all three",
			judged, refused, plainGetsWrong)
	}
}

func verdict(emptied string) string {
	if emptied == "" {
		return "accepts the route"
	}
	return fmt.Sprintf("refuses it on %s", emptied)
}

// TestTheJudgementReadsTheDeclarationNotTheBuild: the verdict follows the
// declaration it is handed. A hand-built declaration for a build whose default
// profile offers one cipher makes a ban on that cipher empty the axis, and one
// whose default offers a cipher this build does not makes a ban on this build's
// whole list leave something. So the judgement reads the declaration and not
// the build, which is what lets it be right about another build during a
// rolling upgrade.
func TestTheJudgementReadsTheDeclarationNotTheBuild(t *testing.T) {
	this := thisBuildsDeclaration()
	if this.AlgorithmProfiles[0].Profile != AlgorithmProfileDefault {
		t.Fatalf("the first declared profile is %q, want default", this.AlgorithmProfiles[0].Profile)
	}
	defaultCiphers := this.AlgorithmProfiles[0].Ciphers
	remaining := defaultCiphers[len(defaultCiphers)-1]

	narrow := this.Clone()
	narrow.AlgorithmProfiles[0].Ciphers = []string{remaining}
	wide := this.Clone()
	wide.AlgorithmProfiles[0].Ciphers = append(wide.AlgorithmProfiles[0].Ciphers, "aes256-gcm-next@example.com")

	for _, c := range []struct {
		name string
		caps *ProxyCapabilities
		bans map[string][]string
		want string
	}{
		{"this build, a ban on " + remaining, this, map[string][]string{"ciphers": {remaining}}, ""},
		{"a build offering only " + remaining + ", the same ban", narrow, map[string][]string{"ciphers": {remaining}}, "ciphers"},
		{"this build, a ban on every default cipher", this, map[string][]string{"ciphers": defaultCiphers}, "ciphers"},
		{"a build offering one more cipher, the same ban", wide, map[string][]string{"ciphers": defaultCiphers}, ""},
	} {
		got, ok := decodeDeclaration(t, c.caps).judge("default", "", c.bans, true)
		if !ok || got != c.want {
			t.Errorf("%s: the judgement %s (covered %v), want it to %s", c.name, verdict(got), ok, verdict(c.want))
		}
	}

	// And a declaration that omits the profile is unknown, never a verdict.
	partial := this.Clone()
	partial.AlgorithmProfiles = partial.AlgorithmProfiles[:1]
	if _, ok := decodeDeclaration(t, partial).judge("legacy-device", "", nil, true); ok {
		t.Error("a profile the declaration does not list was judged")
	}
}

// TestCloneCopiesTheProfileDeclaration: every authorize request carries a clone
// of the build's declaration (internal/routing), so the clone must share no list
// with it, and the promoted Algorithms.Clone must not have cost an entry its
// profile.
func TestCloneCopiesTheProfileDeclaration(t *testing.T) {
	caps := &ProxyCapabilities{AlgorithmProfiles: AlgorithmProfileCapabilities()}
	clone := caps.Clone()
	if !reflect.DeepEqual(clone, caps) {
		t.Fatalf("Clone = %+v, want %+v", clone, caps)
	}
	for i := range clone.AlgorithmProfiles {
		entry := &clone.AlgorithmProfiles[i]
		entry.Profile = "mutated"
		entry.KeyExchanges[0] = "mutated"
		entry.Ciphers[0] = "mutated"
		entry.MACs[0] = "mutated"
		entry.HostKeys[0] = "mutated"
		entry.PublicKeyAuths[0] = "mutated"
	}
	if !reflect.DeepEqual(caps.AlgorithmProfiles, AlgorithmProfileCapabilities()) {
		t.Error("mutating the clone's profile declaration reached back into the original")
	}
	if (&ProxyCapabilities{}).Clone().AlgorithmProfiles != nil {
		t.Error("an absent declaration became a present, empty one")
	}
}
