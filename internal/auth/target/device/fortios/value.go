// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package fortios

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
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
var profilePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,34}$`)

// maxAccountNameLen is the administrator-name length FortiOS accepts.
//
// Verified against Fortinet's naming-rules guidance, which puts most name
// fields at 35 characters (see the package comment for the sources). It is
// above PLAN §5.3's threshold of 32, so FortiOS uses the READABLE naming
// scheme: an administrator on the device names the person it belongs to, which
// is the property the constrained scheme has to give up.
const maxAccountNameLen = 35

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

// trustHost renders a source address as the `<address> <netmask>` pair
// `set trusthost1` expects.
//
// A bare address is pinned as a /32 or /128 rather than widened to its
// enclosing network: this restriction exists to say "only from the proxy", and
// a helpful widening of it would be a silently weaker restriction than the one
// the provisioner believed it applied.
func trustHost(source string) (string, error) {
	if source == "" {
		return "", fmt.Errorf("%w: an empty source address", errInvalidValue)
	}
	if ip := net.ParseIP(source); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String() + " 255.255.255.255", nil
		}
		return ip.String() + "/128", nil
	}
	if _, cidr, err := net.ParseCIDR(source); err == nil {
		if v4 := cidr.IP.To4(); v4 != nil {
			mask := net.IP(cidr.Mask).String()
			return v4.String() + " " + mask, nil
		}
		return cidr.String(), nil
	}
	return "", fmt.Errorf("%w: %q is not an address or a network", errInvalidValue, source)
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
