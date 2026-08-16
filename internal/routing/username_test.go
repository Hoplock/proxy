// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package routing

import (
	"errors"
	"strings"
	"testing"
)

func TestParseUsername(t *testing.T) {
	tests := []struct {
		name       string
		username   string
		delimiter  string
		wantLogin  string
		wantTarget string
		wantErr    error
	}{
		{
			name:       "login and target",
			username:   "alice#host.company.com",
			delimiter:  "#",
			wantLogin:  "alice",
			wantTarget: "host.company.com",
		},
		{
			name:       "target is lowercased and the root dot dropped",
			username:   "alice#HOST.Company.COM.",
			delimiter:  "#",
			wantLogin:  "alice",
			wantTarget: "host.company.com",
		},
		{
			name:       "IPv4 target",
			username:   "alice#192.0.2.10",
			delimiter:  "#",
			wantLogin:  "alice",
			wantTarget: "192.0.2.10",
		},
		{
			name:       "alternative delimiter",
			username:   "alice+host.company.com",
			delimiter:  "+",
			wantLogin:  "alice",
			wantTarget: "host.company.com",
		},
		{
			name:       "login may contain a dot",
			username:   "alice.smith#host.company.com",
			delimiter:  "#",
			wantLogin:  "alice.smith",
			wantTarget: "host.company.com",
		},
		{
			name:      "no delimiter",
			username:  "alice",
			delimiter: "#",
			wantErr:   ErrMalformedUsername,
		},
		{
			// Two delimiters cannot be split without guessing, and a wrong
			// guess connects the user to a different host than they asked for.
			name:      "two delimiters",
			username:  "alice#host#other",
			delimiter: "#",
			wantErr:   ErrMalformedUsername,
		},
		{
			name:      "empty login",
			username:  "#host.company.com",
			delimiter: "#",
			wantErr:   ErrMalformedUsername,
		},
		{
			name:      "empty target",
			username:  "alice#",
			delimiter: "#",
			wantErr:   ErrMalformedUsername,
		},
		{
			name:      "login with whitespace",
			username:  "alice smith#host.company.com",
			delimiter: "#",
			wantErr:   ErrMalformedUsername,
		},
		{
			name:      "delimiter is not one character",
			username:  "alice##host",
			delimiter: "##",
			wantErr:   ErrMalformedUsername,
		},
		{
			name:      "target with a control character",
			username:  "alice#host\ncompany.com",
			delimiter: "#",
			wantErr:   ErrInvalidTarget,
		},
		{
			name:      "target label ends with a hyphen",
			username:  "alice#host-.company.com",
			delimiter: "#",
			wantErr:   ErrInvalidTarget,
		},
		{
			name:      "target with an empty label",
			username:  "alice#host..company.com",
			delimiter: "#",
			wantErr:   ErrInvalidTarget,
		},
		{
			name:      "target too long",
			username:  "alice#" + strings.Repeat("a", 254),
			delimiter: "#",
			wantErr:   ErrInvalidTarget,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			login, target, err := ParseUsername(tt.username, tt.delimiter)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseUsername(%q) error = %v, want errors.Is(..., %v)", tt.username, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseUsername(%q) returned error: %v", tt.username, err)
			}
			if login != tt.wantLogin {
				t.Errorf("login = %q, want %q", login, tt.wantLogin)
			}
			if target != tt.wantTarget {
				t.Errorf("target = %q, want %q", target, tt.wantTarget)
			}
		})
	}
}

// TestParseUsernameErrorsDoNotEchoTheWholeUsername is a small disclosure
// property: the parse error is logged, and a username is attacker-controlled.
// It may name what was wrong, but it must not become a way to write arbitrary
// text into a log line.
func TestParseUsernameErrorsAreBounded(t *testing.T) {
	long := strings.Repeat("x", 500) + "#host.company.com"
	_, _, err := ParseUsername(long, "#")
	if err == nil {
		t.Fatal("a 500-character login was accepted")
	}
	if strings.Contains(err.Error(), long) {
		t.Error("the error repeats the whole username back")
	}
}
