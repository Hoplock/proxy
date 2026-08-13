// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package config

import (
	"errors"
	"strings"
	"testing"
)

// exampleConfigPath is the operator-facing example that ships with the repo;
// it must always be a valid config.
const exampleConfigPath = "../../config.example.yaml"

func TestLoadExampleConfig(t *testing.T) {
	cfg, err := Load(exampleConfigPath)
	if err != nil {
		t.Fatalf("Load(%s) returned error: %v", exampleConfigPath, err)
	}

	if got, want := cfg.Bastion.ListenAddr, "0.0.0.0:2222"; got != want {
		t.Errorf("ListenAddr = %q, want %q", got, want)
	}
	if got, want := cfg.Bastion.HostKeyPath, "/etc/securecommandproxy/host_key"; got != want {
		t.Errorf("HostKeyPath = %q, want %q", got, want)
	}
	if got, want := cfg.Management.BaseURL, "https://management.example.com"; got != want {
		t.Errorf("BaseURL = %q, want %q", got, want)
	}
	if got, want := cfg.Routing.TargetDelimiter, DefaultTargetDelimiter; got != want {
		t.Errorf("TargetDelimiter = %q, want %q", got, want)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("testdata/does-not-exist.yaml"); err == nil {
		t.Fatal("Load of a missing file returned nil error")
	}
}

const minimalConfig = `
bastion:
  listen_addr: "0.0.0.0:2222"
  host_key_path: "/etc/securecommandproxy/host_key"
management:
  base_url: "https://management.example.com"
`

func TestParseAppliesDelimiterDefault(t *testing.T) {
	cfg, err := Parse(strings.NewReader(minimalConfig))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if got, want := cfg.Routing.TargetDelimiter, DefaultTargetDelimiter; got != want {
		t.Errorf("TargetDelimiter = %q, want %q (default)", got, want)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  error
	}{
		{
			name:  "not yaml",
			input: "bastion: [this is not: valid\n",
			want:  ErrMalformed,
		},
		{
			name:  "empty file",
			input: "",
			want:  ErrMalformed,
		},
		{
			name: "unknown field",
			input: minimalConfig + `
routing:
  target_delimeter: "#"
`,
			want: ErrMalformed,
		},
		{
			name: "wrong type",
			input: `
bastion:
  listen_addr: ["0.0.0.0:2222"]
  host_key_path: "/etc/securecommandproxy/host_key"
management:
  base_url: "https://management.example.com"
`,
			want: ErrMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse(strings.NewReader(tt.input))
			if err == nil {
				t.Fatalf("Parse(%q) = %+v, want error", tt.name, cfg)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("Parse error = %v, want errors.Is(..., %v)", err, tt.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	valid := func() Config {
		return Config{
			Bastion:    Bastion{ListenAddr: "0.0.0.0:2222", HostKeyPath: "/etc/host_key"},
			Management: Management{BaseURL: "https://management.example.com"},
			Routing:    Routing{TargetDelimiter: DefaultTargetDelimiter},
		}
	}

	tests := []struct {
		name      string
		mutate    func(*Config)
		wantField string
		wantCause error
	}{
		{name: "valid"},
		{
			name:      "missing listen addr",
			mutate:    func(c *Config) { c.Bastion.ListenAddr = "" },
			wantField: "bastion.listen_addr",
			wantCause: ErrMissing,
		},
		{
			name:      "listen addr without port",
			mutate:    func(c *Config) { c.Bastion.ListenAddr = "0.0.0.0" },
			wantField: "bastion.listen_addr",
			wantCause: ErrInvalid,
		},
		{
			name:      "missing host key path",
			mutate:    func(c *Config) { c.Bastion.HostKeyPath = "" },
			wantField: "bastion.host_key_path",
			wantCause: ErrMissing,
		},
		{
			name:      "missing base url",
			mutate:    func(c *Config) { c.Management.BaseURL = "" },
			wantField: "management.base_url",
			wantCause: ErrMissing,
		},
		{
			name:      "base url without scheme",
			mutate:    func(c *Config) { c.Management.BaseURL = "management.example.com" },
			wantField: "management.base_url",
			wantCause: ErrInvalid,
		},
		{
			name:      "base url with wrong scheme",
			mutate:    func(c *Config) { c.Management.BaseURL = "ftp://management.example.com" },
			wantField: "management.base_url",
			wantCause: ErrInvalid,
		},
		{
			name:      "delimiter too long",
			mutate:    func(c *Config) { c.Routing.TargetDelimiter = "##" },
			wantField: "routing.target_delimiter",
			wantCause: ErrInvalid,
		},
		{
			name:      "alphanumeric delimiter",
			mutate:    func(c *Config) { c.Routing.TargetDelimiter = "x" },
			wantField: "routing.target_delimiter",
			wantCause: ErrInvalid,
		},
		{
			name:      "hostname character delimiter",
			mutate:    func(c *Config) { c.Routing.TargetDelimiter = "." },
			wantField: "routing.target_delimiter",
			wantCause: ErrInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid()
			if tt.mutate != nil {
				tt.mutate(&cfg)
			}

			err := cfg.Validate()
			if tt.wantField == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}

			if err == nil {
				t.Fatal("Validate() = nil, want error")
			}
			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("Validate() error type = %T, want *ValidationError", err)
			}
			if len(verr.Fields) != 1 {
				t.Fatalf("Validate() reported %d fields (%v), want 1", len(verr.Fields), err)
			}
			if got := verr.Fields[0].Field; got != tt.wantField {
				t.Errorf("field = %q, want %q", got, tt.wantField)
			}
			if !errors.Is(err, tt.wantCause) {
				t.Errorf("cause = %v, want errors.Is(..., %v)", err, tt.wantCause)
			}
		})
	}
}

func TestValidateReportsAllFields(t *testing.T) {
	cfg := Config{Routing: Routing{TargetDelimiter: "x"}}

	err := cfg.Validate()
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("Validate() error = %v (%T), want *ValidationError", err, err)
	}
	if got, want := len(verr.Fields), 4; got != want {
		t.Fatalf("Validate() reported %d fields (%v), want %d", got, err, want)
	}
	if !errors.Is(err, ErrMissing) || !errors.Is(err, ErrInvalid) {
		t.Errorf("Validate() error = %v, want it to wrap both ErrMissing and ErrInvalid", err)
	}
}
