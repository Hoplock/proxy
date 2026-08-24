// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package filter

import (
	"strings"
	"testing"

	"github.com/hoplock/proxy/internal/control"
)

// restrictedPolicy is the estate in these tests: a monitoring account that may
// read one log, ask systemctl about a fixed set of units, and nothing else.
func restrictedPolicy(commands ...control.RestrictedCommand) control.FilterPolicy {
	return control.FilterPolicy{
		Mode:           control.FilterModeWhitelist,
		ExecMode:       control.ExecModeRestricted,
		RestrictedExec: &control.RestrictedExecPolicy{Commands: commands},
	}
}

var (
	exactUptime = control.RestrictedCommand{
		Executable: "/usr/bin/uptime",
		Form:       control.CommandFormExact,
	}
	exactTailLog = control.RestrictedCommand{
		Executable: "/usr/bin/tail",
		Form:       control.CommandFormExact,
		Argv:       []string{"-n", "100", "/var/log/app.log"},
	}
	positionalSystemctl = control.RestrictedCommand{
		Executable: "/usr/bin/systemctl",
		Form:       control.CommandFormPositional,
		Args: []control.ArgumentSpec{
			{Kind: control.ArgumentOneOf, Values: []string{"status", "is-active"}},
			{Kind: control.ArgumentPrefix, Value: "app-"},
			{Kind: control.ArgumentLiteral, Value: "--no-pager", Optional: true},
		},
	}
)

// TestRestrictedExecPermitsOnlyTheShapesTheServerWrote is the boundary: an
// approved vector runs, and everything about it that the server did not name is
// denied.
func TestRestrictedExecPermitsOnlyTheShapesTheServerWrote(t *testing.T) {
	e := mustEngine(t, restrictedPolicy(exactUptime, exactTailLog, positionalSystemctl))

	permitted := []string{
		"/usr/bin/uptime",
		"/usr/bin/tail -n 100 /var/log/app.log",
		"/usr/bin/systemctl status app-web",
		"/usr/bin/systemctl is-active app-web --no-pager",
		"/usr/bin/tail -n 100 '/var/log/app.log'", // quoting the server's own value
	}
	for _, command := range permitted {
		got := e.Exec(command)
		if got.Blocks() {
			t.Errorf("Exec(%q) was denied (%s), want it permitted", command, got.Detail)
		}
		if got.Tier != TierRestricted {
			t.Errorf("Exec(%q).Tier = %q, want %q", command, got.Tier, TierRestricted)
		}
	}

	denied := map[string]string{
		"an argument outside its shape":     "/usr/bin/systemctl status database-primary",
		"a verb outside the oneof":          "/usr/bin/systemctl restart app-web",
		"an argument no spec covers":        "/usr/bin/systemctl status app-web --no-pager --now",
		"an optional position filled wrong": "/usr/bin/systemctl status app-web --pager",
		"an executable nobody named":        "/usr/bin/cat /etc/shadow",
		"the same tool by another path":     "/bin/uptime",
		"the same tool by basename":         "uptime",
		"an exact form with extra argv":     "/usr/bin/tail -n 100 /var/log/app.log /etc/shadow",
		"an exact form missing argv":        "/usr/bin/tail -n 100",
		"an approved name with any argv":    "/usr/bin/uptime --pretty",
	}
	for name, command := range denied {
		got := e.Exec(command)
		if !got.Blocks() {
			t.Errorf("%s: Exec(%q) was permitted, want it denied", name, command)
		}
		if got.Action != control.FilterActionBlockCommand {
			t.Errorf("%s: action = %q, want %q", name, got.Action, control.FilterActionBlockCommand)
		}
	}

	// An empty permitted list is a coherent policy: a route that may log in and
	// run nothing.
	if got := mustEngine(t, restrictedPolicy()).Exec("/usr/bin/uptime"); !got.Blocks() {
		t.Errorf("an empty restricted list permitted %+v", got)
	}
}

// TestACommandThatDoesNotParseUnambiguouslyIsDenied is the rule the whole tier
// rests on. An ambiguous parse inside a default-deny boundary is not a bug in
// one branch, it is the vulnerability class.
func TestACommandThatDoesNotParseUnambiguouslyIsDenied(t *testing.T) {
	e := mustEngine(t, restrictedPolicy(exactUptime, positionalSystemctl))

	unparseable := map[string]string{
		"a second command":               "/usr/bin/uptime; rm -rf /",
		"a pipeline":                     "/usr/bin/uptime | sh",
		"a background job":               "/usr/bin/uptime & rm -rf /",
		"command substitution":           "/usr/bin/systemctl status app-$(whoami)",
		"backquotes":                     "/usr/bin/systemctl status app-`whoami`",
		"a variable":                     "/usr/bin/systemctl status app-${TARGET}",
		"a variable inside quotes":       `/usr/bin/systemctl status "app-$TARGET"`,
		"a redirect":                     "/usr/bin/uptime > /etc/cron.d/mine",
		"an embedded newline":            "/usr/bin/uptime\nrm -rf /",
		"a carriage return":              "/usr/bin/uptime\rrm -rf /",
		"an embedded NUL":                "/usr/bin/uptime\x00rm -rf /",
		"a NUL inside single quotes":     "/usr/bin/systemctl status 'app-\x00web'",
		"invalid UTF-8":                  "/usr/bin/systemctl status app-\xff\xfe",
		"an unterminated single quote":   "/usr/bin/systemctl status 'app-web",
		"an unterminated double quote":   `/usr/bin/systemctl status "app-web`,
		"a glob the target would expand": "/usr/bin/systemctl status app-*",
		"a backslash escape":             `/usr/bin/systemctl status app-\ web`,
		"tilde expansion":                "/usr/bin/tail ~/notes",
		"an empty command":               "   ",
	}
	for name, command := range unparseable {
		got := e.Exec(command)
		if !got.Blocks() {
			t.Errorf("%s: Exec(%q) was permitted, want it denied", name, command)
		}
		if !strings.Contains(got.Detail, "unambiguous") {
			t.Errorf("%s: detail = %q, want it to say the command did not parse", name, got.Detail)
		}
	}
}

// TestQuotingSurvivesTheParseExactly checks the parser against the one shell
// behaviour it does model: quote removal. What comes out has to be what the
// target's own shell would produce, or the vector the proxy approved is not the
// vector that runs.
func TestQuotingSurvivesTheParseExactly(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    []string
	}{
		{"ls", []string{"ls"}},
		{"  ls   -l  ", []string{"ls", "-l"}},
		{"ls\t-l", []string{"ls", "-l"}},
		{"grep 'error code' /var/log/app.log", []string{"grep", "error code", "/var/log/app.log"}},
		{`grep "error code" /var/log/app.log`, []string{"grep", "error code", "/var/log/app.log"}},
		{"grep '*.log' .", []string{"grep", "*.log", "."}},
		{"echo ''", []string{"echo", ""}},
		{"echo a''b", []string{"echo", "ab"}},
		{"echo 'héllo wörld'", []string{"echo", "héllo wörld"}},
	} {
		got, err := ParseArgv(tc.command)
		if err != nil {
			t.Errorf("ParseArgv(%q): %v", tc.command, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("ParseArgv(%q) = %q, want %q", tc.command, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("ParseArgv(%q) = %q, want %q", tc.command, got, tc.want)
				break
			}
		}
	}
}

// TestArgumentKindsMatchTheirShapes covers each spec kind on its own, including
// the one that constrains nothing and is named so a reviewer can find it.
func TestArgumentKindsMatchTheirShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec control.ArgumentSpec
		arg  string
		want bool
	}{
		{"literal matches", control.ArgumentSpec{Kind: control.ArgumentLiteral, Value: "--all"}, "--all", true},
		{"literal is exact", control.ArgumentSpec{Kind: control.ArgumentLiteral, Value: "--all"}, "--all-of-it", false},
		{"prefix matches", control.ArgumentSpec{Kind: control.ArgumentPrefix, Value: "app-"}, "app-web", true},
		{"prefix is a prefix", control.ArgumentSpec{Kind: control.ArgumentPrefix, Value: "app-"}, "db-app-web", false},
		{"oneof matches a member", control.ArgumentSpec{Kind: control.ArgumentOneOf, Values: []string{"status", "stop"}}, "stop", true},
		{"oneof rejects a stranger", control.ArgumentSpec{Kind: control.ArgumentOneOf, Values: []string{"status", "stop"}}, "start", false},
		{"any takes anything", control.ArgumentSpec{Kind: control.ArgumentAny}, "--force", true},
		{"an unknown kind denies", control.ArgumentSpec{Kind: "regex"}, "anything", false},
	} {
		if got := matchArgument(tc.spec, tc.arg); got != tc.want {
			t.Errorf("%s: matchArgument(%+v, %q) = %t, want %t", tc.name, tc.spec, tc.arg, got, tc.want)
		}
	}
}
