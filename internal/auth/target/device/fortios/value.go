// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package fortios

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Value handling at the boundary, in the spirit of internal/auth/target/script.go.
//
// The far end is a CONFIGURATION PARSER on production network equipment, so the
// stakes here are not "a command fails". A value that escapes its quoting does
// not produce an error; it produces a configuration change nobody asked for, on
// a firewall, applied to live traffic. Everything interpolated into a command
// is therefore validated against what it is FOR and then quoted anyway — belt
// and braces, exactly as the POSIX path does it, and for the same reason: the
// validation is a property of today's callers and the quoting is a property of
// the string.

// errInvalidValue means a value could not be safely put into a FortiOS command.
var errInvalidValue = errors.New("auth/target/device/fortios: invalid value for a device command")

// accountNamePattern is what this driver will put after `edit`.
//
// It is narrower than what FortiOS accepts, and deliberately: the only names
// this driver ever creates are the ones internal/auth/target's naming scheme
// produces, which are base36 and hyphens. Accepting more would widen the
// blast radius of a bug elsewhere for no benefit here. Fortinet added
// character restrictions on administrator names in FortiOS 7.4/7.6 to defeat
// homoglyph attacks; this set is inside every version of those rules.
var accountNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// profilePattern is what this driver will put after `set accprofile`.
//
// Access profile names are the customer's — `prof_admin`, or something their
// own build named — so this is the FortiOS object-name character set rather
// than ours. It is still an allow-list: a profile name arrives from proxy
// configuration, and configuration is a thing an operator edits, not a thing
// this driver may assume is well formed.
//
// The 35-character cap is the documented one for this field: `config system
// admin`'s `accprofile` is `string, Maximum length: 35`. Phase 0014 reached the
// same number from a general "most name fields accept 35 characters" line in
// the naming-rules KB, which is right here and wrong for the administrator
// name — see maxAccountNameLen.
var profilePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,34}$`)

// maxAccountNameLen is the administrator-name length FortiOS accepts.
//
// It is 64. `config system admin`'s `name` parameter is `string, Maximum
// length: 64`, identical in 7.0.17, 7.2.11, 7.4.9, 7.6.6 and 8.0.0
// (docs/FORTIOS-DOC-VERIFICATION.md, claim 1). Phase 0014 declared 35, taken
// from the naming-rules KB's general "most name fields accept 35 characters" —
// guidance about *most* fields rather than about this one.
//
// The correction changes no behaviour: both figures clear PLAN §5.3's threshold
// of 32, so FortiOS uses the READABLE naming scheme either way — an
// administrator on the device names the person it belongs to, which is the
// property the constrained scheme has to give up. It is declared at the real
// limit rather than kept at the old one because a declaration is a claim about
// the platform, and a narrowing nobody needs is a claim that is simply untrue.
const maxAccountNameLen = 64

// validateAccountName gates the one value that reaches `edit`, `delete`, and
// every `set` in between.
func validateAccountName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: an empty administrator name", errInvalidValue)
	case len(name) > maxAccountNameLen:
		return fmt.Errorf("%w: %q is longer than the %d characters FortiOS accepts",
			errInvalidValue, name, maxAccountNameLen)
	case !accountNamePattern.MatchString(name):
		return fmt.Errorf("%w: %q is not a name this driver creates", errInvalidValue, name)
	}
	return nil
}

// validateProfile gates `set accprofile`.
func validateProfile(profile string) error {
	if profile == "" {
		return fmt.Errorf("%w: an empty access profile", errInvalidValue)
	}
	if !profilePattern.MatchString(profile) {
		return fmt.Errorf("%w: %q is not a usable access profile name", errInvalidValue, profile)
	}
	return nil
}

// vdomPattern is what this driver will put after `set vdom`.
//
// A VDOM name is the CUSTOMER'S — it names a partition they created, in their
// own scheme — so this is the FortiOS object-name character set rather than the
// narrow one this driver's own account names use. It is still an allow-list,
// and for the sharper of the two reasons: the value arrives from a policy
// server over the wire, and it is interpolated into a configuration command on
// a firewall.
var vdomPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// maxVDOMNameLen is the length `config system admin`'s `vdom` field accepts:
// "Virtual domain(s) that the administrator can access", string, maximum
// length 79 (docs/FORTIOS-DOC-VERIFICATION.md, "Beyond the ten claims").
//
// It is the length of the FIELD THIS DRIVER WRITES, which is the one it can
// check. What a `config system vdom` entry itself may be named is a different
// and shorter limit that no page read for this phase stated; a name too long
// for the unit fails the existence check before anything is created, so nothing
// here depends on knowing it.
const maxVDOMNameLen = 79

// validateVDOM gates `set vdom`.
func validateVDOM(vdom string) error {
	switch {
	case vdom == "":
		return fmt.Errorf("%w: an empty virtual domain", errInvalidValue)
	case len(vdom) > maxVDOMNameLen:
		return fmt.Errorf("%w: %q is longer than the %d characters the `vdom` field accepts",
			errInvalidValue, vdom, maxVDOMNameLen)
	case !vdomPattern.MatchString(vdom):
		return fmt.Errorf("%w: %q is not a usable virtual domain name", errInvalidValue, vdom)
	}
	return nil
}

// closedIPv6TrustHost is what `set ip6-trusthost1` is given when the account is
// pinned to an IPv4 address.
//
// It has to be given something. `ip6-trusthost1`..`10` are ten fields parallel
// to `trusthost1`..`10`, of type `ipv6-prefix`, and they default to `::/0` —
// "Default allows access from any IPv6 address". Phase 0014 wrote only
// `trusthost1`, so an administrator the provisioner believed was pinned to the
// proxy stayed reachable from ANY IPv6 address on a unit with IPv6 management
// access. That is precisely the failure trustHost's own comment argues against,
// arriving through the field the driver did not set rather than through a
// widened mask.
//
// `::/128` is the unspecified address and nothing else: no host sources traffic
// from it, so the prefix matches nothing that can connect. That reading follows
// from what a /128 prefix means rather than from a Fortinet statement about
// this field — the documentation says what the DEFAULT allows and does not
// enumerate how to close it — so it is on the hardware list in this phase's
// learnings rather than presented as documented.
const closedIPv6TrustHost = "::/128"

// trustHost renders a source address as the `<address> <netmask>` pair
// `set trusthost1` expects.
//
// A bare address is pinned as a /32 rather than widened to its enclosing
// network: this restriction exists to say "only from the proxy", and a helpful
// widening of it would be a silently weaker restriction than the one the
// provisioner believed it applied.
//
// IPv4 ONLY, and an IPv6 source is refused rather than rendered. `trusthost1`
// is an `ipv4-classnet` field; phase 0014 rendered an IPv6 source as
// `<addr>/128` and wrote it there anyway, which the device would reject —
// making an IPv6-fronted proxy fail at create time with a parse error instead
// of a sentence naming the limitation. Pinning IPv6 properly means writing
// `set ip6-trusthost1` with the real address and closing `trusthost1` against
// IPv4, and the value that closes an `ipv4-classnet` field is not documented
// anywhere this phase could check. Refusing is the honest half of the choice
// docs/FORTIOS-DOC-VERIFICATION.md's claim 9 leaves open; supporting it is
// listed as follow-up work rather than guessed at.
func trustHost(source string) (string, error) {
	if source == "" {
		return "", fmt.Errorf("%w: an empty source address", errInvalidValue)
	}
	if ip := net.ParseIP(source); ip != nil {
		v4 := ip.To4()
		if v4 == nil {
			return "", errIPv6SourceAddress(source)
		}
		return v4.String() + " 255.255.255.255", nil
	}
	if _, cidr, err := net.ParseCIDR(source); err == nil {
		v4 := cidr.IP.To4()
		if v4 == nil {
			return "", errIPv6SourceAddress(source)
		}
		mask := net.IP(cidr.Mask).String()
		return v4.String() + " " + mask, nil
	}
	return "", fmt.Errorf("%w: %q is not an address or a network", errInvalidValue, source)
}

// errIPv6SourceAddress says why an IPv6 proxy address cannot be pinned yet.
//
// It is NOT device.ErrUnsupported. That error means the PLATFORM cannot do
// this, and the platform can: `ip6-trusthost1` exists. This driver cannot, and
// the difference matters because ErrUnsupported would skip the ladder rung and
// serve the session on a credential the server ranked lower, while this fails
// the attempt — which is the right answer for a restriction the route asked for
// and this build cannot apply.
func errIPv6SourceAddress(source string) error {
	return fmt.Errorf("%w: %q is an IPv6 address, and this driver pins an administrator "+
		"through `set trusthost1`, which is an IPv4 field", errInvalidValue, source)
}

// validatePublicKey gates `set ssh-public-key1`.
//
// A public key is public, so the value may be echoed in an error — but it is
// still one line of a configuration file, and the newline check is what keeps
// it one line.
func validatePublicKey(key string) error {
	key = strings.TrimSpace(key)
	switch {
	case key == "":
		return fmt.Errorf("%w: an empty public key", errInvalidValue)
	case strings.ContainsAny(key, "\r\n\x00"):
		return fmt.Errorf("%w: a public key containing a newline", errInvalidValue)
	case !strings.HasPrefix(key, "ssh-") && !strings.HasPrefix(key, "ecdsa-"):
		// FortiOS documents RSA, ECDSA and EdDSA for `ssh-public-key1..3`, so
		// these two prefixes cover the documented set (`ssh-rsa`,
		// `ssh-ed25519`, `ecdsa-sha2-*`) — by prefix rather than by name, which
		// is worth knowing before anyone reads this as a checked allow-list.
		return fmt.Errorf("%w: %q is not an OpenSSH public key", errInvalidValue, key)
	}
	return nil
}

// validateSecret gates a password on its way into `set password`.
//
// The value is NEVER echoed, here or anywhere: this is the one interpolated
// value in the driver that is credential material, and an error message is a
// log line. What is checked is only whether it can be carried safely — a quote
// or a newline in a password would end the command and start another.
func validateSecret(secret string) error {
	switch {
	case secret == "":
		return fmt.Errorf("%w: an empty password", errInvalidValue)
	case strings.ContainsAny(secret, "\"'\r\n\x00"):
		return fmt.Errorf("%w: the generated password contains a character FortiOS cannot carry", errInvalidValue)
	}
	return nil
}

// quote wraps a value for the FortiOS parser.
//
// FortiOS takes a double-quoted string and understands a backslash escape
// inside it. Every value that reaches here has already been validated against
// a pattern that excludes both characters, so this should never have anything
// to do — it does it anyway, because "validated upstream" describes today's
// callers and this string is going into a firewall's configuration.
func quote(v string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + replacer.Replace(v) + `"`
}

// maxScheduleNameLen is the longest name this driver gives a schedule object.
//
// TWO DOCUMENTED FIGURES DISAGREE and this takes the smaller (phase 0017).
// `config system admin`'s `schedule` field is `string, Maximum length: 35`,
// while the naming-rules KB gives 32 characters for "schedule names" — the
// object's own limit rather than the reference field's. Nothing read for this
// phase reconciles them, so the driver spends the smaller: the difference is
// one character of token, and being wrong in the other direction is a name the
// device truncates or refuses at the moment it is creating a privileged
// account's expiry.
//
// Nothing this proxy creates comes near it. The naming scheme in
// internal/auth/target never emits a name longer than 32 characters on ANY
// platform (PLAN §5.3's readable scheme caps there), which is what makes the
// decision below — the schedule takes the administrator's own name — fit
// without a second budget.
const maxScheduleNameLen = 32

// validateScheduleName gates the name that reaches `edit` in the schedule table
// and `set schedule` on the administrator.
//
// It is the account name's own validation against the schedule limit, because
// the two objects share a name: the schedule carries the reaper prefix and the
// uniqueness token by BEING the account name, rather than by having a second
// scheme that has to be kept in step with the first. What this check exists for
// is the one case where the shared name does not fit — a platform limit of 64
// on the administrator and 32 on the schedule is a gap a future naming change
// could walk into, and it must fail here rather than on the device, after the
// schedule is created and before the administrator is.
func validateScheduleName(name string) error {
	if err := validateAccountName(name); err != nil {
		return err
	}
	if len(name) > maxScheduleNameLen {
		return fmt.Errorf("%w: %q is %d characters and a FortiOS schedule name is limited to %d, "+
			"so this administrator cannot carry a device-enforced expiry",
			errInvalidValue, name, len(name), maxScheduleNameLen)
	}
	return nil
}

// scheduleGranularity is the resolution of a one-time schedule.
//
// `set start` and `set end` are `hh:mm yyyy/mm/dd`: there are no seconds in the
// format, so a deadline is expressible only to the minute.
const scheduleGranularity = time.Minute

// scheduleTimeLayout renders that format.
const scheduleTimeLayout = "15:04 2006/01/02"

// scheduleTimePattern is the last gate before a rendered datetime is sent.
//
// Every value this driver interpolates is validated and then quoted; this one
// is validated and NOT quoted, which is the single exception in the file and so
// gets the stricter check. `set start {hh:mm yyyy/mm/dd}` is a value with a
// space in it, and whether the FortiOS parser accepts that value quoted is not
// documented anywhere this phase could reach — Fortinet's own examples show it
// bare. Quoting on a guess would turn every device-enforced session into a
// parse error; sending it bare is what the documentation shows.
//
// What makes that safe is not the quoting it does not have: it is that the
// string cannot carry anything. It is produced by time.Format from a time
// value, so the only characters it can contain are digits, a colon, a slash and
// one space — and this pattern is what says so at the boundary rather than
// two hundred lines away where the formatting happens.
var scheduleTimePattern = regexp.MustCompile(`^\d{2}:\d{2} \d{4}/\d{2}/\d{2}$`)

// scheduleWindow renders the start and end of the account's window, in the
// DEVICE's own wall-clock time.
//
// Two properties, and each is a decision:
//
// The window is computed from the DEVICE's clock, never this proxy's. `set end`
// is an absolute local datetime on the unit, so a proxy in UTC writing a window
// for a firewall in UTC+8 would either lock the account out for eight hours or
// hold it open for eight hours past its deadline. The second is a security
// failure and it is silent — the audit record would say the device holds a
// deadline it does not hold.
//
// The end is TRUNCATED to the granularity, never rounded up. Truncation can
// only make the window end at or before the deadline the route asked for, and
// on this platform "expiry" means the device stops accepting authentications:
// finishing up to 59 seconds early costs a session nothing it can notice, while
// rounding up would hand out time nobody authorised. The same truncation
// applied to the start opens the window at or before now, which is what keeps a
// second of skew between reading the clock and writing the object from
// producing an account that cannot log in at all.
func scheduleWindow(deviceNow time.Time, lifetime time.Duration) (start, end string, err error) {
	if lifetime < scheduleGranularity {
		// Refused rather than rounded up. A lifetime FortiOS cannot express is
		// not a lifetime to approximate upwards on a privileged account, and
		// approximating it downwards is an account that has already expired.
		return "", "", fmt.Errorf("%w: a lifetime of %s cannot be rendered onto a FortiOS one-time schedule, "+
			"whose start and end are `hh:mm yyyy/mm/dd` and therefore no finer than %s",
			errInvalidValue, lifetime, scheduleGranularity)
	}
	startAt := deviceNow.Truncate(scheduleGranularity)
	endAt := deviceNow.Add(lifetime).Truncate(scheduleGranularity)
	if !endAt.After(startAt) {
		return "", "", fmt.Errorf("%w: a lifetime of %s leaves no whole minute between the schedule's start and end",
			errInvalidValue, lifetime)
	}
	start, end = startAt.Format(scheduleTimeLayout), endAt.Format(scheduleTimeLayout)
	for _, v := range []string{start, end} {
		if !scheduleTimePattern.MatchString(v) {
			// Unreachable while time.Format holds its contract, and checked
			// because this is the one value that goes to the parser unquoted.
			return "", "", fmt.Errorf("%w: %q is not a schedule datetime", errInvalidValue, v)
		}
	}
	return start, end, nil
}
