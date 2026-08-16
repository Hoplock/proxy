// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package config

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
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
	if got, want := cfg.Auth.User.Methods, DefaultUserAuthMethods(); !reflect.DeepEqual(got, want) {
		t.Errorf("Auth.User.Methods = %v, want %v", got, want)
	}
	if got, want := cfg.Auth.User.MFA.MaxWait, 2*time.Minute; got != want {
		t.Errorf("Auth.User.MFA.MaxWait = %v, want %v", got, want)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("testdata/does-not-exist.yaml"); err == nil {
		t.Fatal("Load of a missing file returned nil error")
	}
}

const minimalConfig = `
bastion:
  id: "bastion-1"
  listen_addr: "0.0.0.0:2222"
  host_key_path: "/etc/securecommandproxy/host_key"
management:
  base_url: "https://management.example.com"
auth:
  target:
    static_key:
      key_path: "/etc/securecommandproxy/target_key"
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
			Bastion:    Bastion{ID: "bastion-1", ListenAddr: "0.0.0.0:2222", HostKeyPath: "/etc/host_key"},
			Management: Management{BaseURL: "https://management.example.com"},
			Routing:    Routing{TargetDelimiter: DefaultTargetDelimiter},
			Auth: Auth{
				User: UserAuth{Methods: DefaultUserAuthMethods()},
				Target: TargetAuth{
					Method:    TargetAuthMethodStaticKey,
					StaticKey: StaticKeyAuth{KeyPath: "/etc/target_key"},
				},
			},
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
	// bastion.id, bastion.listen_addr, bastion.host_key_path,
	// management.base_url, routing.target_delimiter, auth.user.methods, and the
	// unset auth.target.method — every problem in one pass, so an operator can
	// fix the file in a single edit.
	if got, want := len(verr.Fields), 7; got != want {
		t.Fatalf("Validate() reported %d fields (%v), want %d", got, err, want)
	}
	if !errors.Is(err, ErrMissing) || !errors.Is(err, ErrInvalid) {
		t.Errorf("Validate() error = %v, want it to wrap both ErrMissing and ErrInvalid", err)
	}
}

func TestParseAppliesUserAuthDefaults(t *testing.T) {
	cfg, err := Parse(strings.NewReader(minimalConfig))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	want := DefaultUserAuthMethods()
	if got := cfg.Auth.User.Methods; !reflect.DeepEqual(got, want) {
		t.Errorf("Auth.User.Methods = %v, want %v (default)", got, want)
	}
	// The MFA settings have no config-level default: zero means "the package
	// default", which keeps one set of numbers rather than two.
	if got := cfg.Auth.User.MFA; got != (MFA{}) {
		t.Errorf("Auth.User.MFA = %+v, want the zero value", got)
	}
}

// TestParseUserAuthSection covers the shape an operator actually writes,
// including durations as strings.
func TestParseUserAuthSection(t *testing.T) {
	const src = `
bastion:
  id: "bastion-1"
  listen_addr: "0.0.0.0:2222"
  host_key_path: "/etc/securecommandproxy/host_key"
management:
  base_url: "https://management.example.com"
auth:
  user:
    methods: ["cert"]
    mfa:
      min_poll_interval: 250ms
      progress_interval: 3s
      max_wait: 90s
  target:
    static_key:
      key_path: "/etc/securecommandproxy/target_key"
`
	cfg, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if got, want := cfg.Auth.User.Methods, []string{"cert"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Methods = %v, want %v", got, want)
	}
	if got, want := cfg.Auth.User.MFA.MinPollInterval, 250*time.Millisecond; got != want {
		t.Errorf("MinPollInterval = %v, want %v", got, want)
	}
	if got, want := cfg.Auth.User.MFA.ProgressInterval, 3*time.Second; got != want {
		t.Errorf("ProgressInterval = %v, want %v", got, want)
	}
	if got, want := cfg.Auth.User.MFA.MaxWait, 90*time.Second; got != want {
		t.Errorf("MaxWait = %v, want %v", got, want)
	}
}

// TestParseRejectsEmptyMethodList pins the difference between an absent key and
// an explicitly empty one: only the first gets the default. Disabling every
// method must fail loudly rather than be silently undone.
func TestParseRejectsEmptyMethodList(t *testing.T) {
	const src = `
bastion:
  listen_addr: "0.0.0.0:2222"
  host_key_path: "/etc/securecommandproxy/host_key"
management:
  base_url: "https://management.example.com"
auth:
  user:
    methods: []
`
	_, err := Parse(strings.NewReader(src))
	if err == nil {
		t.Fatal("Parse of an empty method list = nil error, want an error")
	}
	if !errors.Is(err, ErrMissing) {
		t.Errorf("Parse error = %v, want errors.Is(..., ErrMissing)", err)
	}
}

func TestValidateAuth(t *testing.T) {
	valid := func() Config {
		return Config{
			Bastion:    Bastion{ID: "bastion-1", ListenAddr: "0.0.0.0:2222", HostKeyPath: "/etc/host_key"},
			Management: Management{BaseURL: "https://management.example.com"},
			Routing:    Routing{TargetDelimiter: DefaultTargetDelimiter},
			Auth: Auth{
				User: UserAuth{Methods: DefaultUserAuthMethods()},
				Target: TargetAuth{
					Method:    TargetAuthMethodStaticKey,
					StaticKey: StaticKeyAuth{KeyPath: "/etc/target_key"},
				},
			},
		}
	}

	tests := []struct {
		name      string
		mutate    func(*Config)
		wantField string
		wantCause error
	}{
		{
			name:      "unknown method",
			mutate:    func(c *Config) { c.Auth.User.Methods = []string{"cert", "kerberos"} },
			wantField: "auth.user.methods[1]",
			wantCause: ErrInvalid,
		},
		{
			name:      "duplicate method",
			mutate:    func(c *Config) { c.Auth.User.Methods = []string{"cert", "cert"} },
			wantField: "auth.user.methods[1]",
			wantCause: ErrInvalid,
		},
		{
			name:      "no methods",
			mutate:    func(c *Config) { c.Auth.User.Methods = nil },
			wantField: "auth.user.methods",
			wantCause: ErrMissing,
		},
		{
			name:      "negative poll interval",
			mutate:    func(c *Config) { c.Auth.User.MFA.MinPollInterval = -time.Second },
			wantField: "auth.user.mfa.min_poll_interval",
			wantCause: ErrInvalid,
		},
		{
			name:      "negative max wait",
			mutate:    func(c *Config) { c.Auth.User.MFA.MaxWait = -time.Minute },
			wantField: "auth.user.mfa.max_wait",
			wantCause: ErrInvalid,
		},
		{
			// Certificate-only is a supported deployment, not a mistake.
			name:   "certificate only",
			mutate: func(c *Config) { c.Auth.User.Methods = []string{"cert"} },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid()
			tt.mutate(&cfg)

			err := cfg.Validate()
			if tt.wantField == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}

			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("Validate() error = %v (%T), want *ValidationError", err, err)
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

// TestValidateProxyAndTargetAuth covers the settings phase 0005 added: the
// bastion's own id, the target authentication plane, and the engine's bounds.
func TestValidateProxyAndTargetAuth(t *testing.T) {
	valid := func() Config {
		return Config{
			Bastion:    Bastion{ID: "bastion-1", ListenAddr: "0.0.0.0:2222", HostKeyPath: "/etc/host_key"},
			Management: Management{BaseURL: "https://management.example.com"},
			Routing:    Routing{TargetDelimiter: DefaultTargetDelimiter},
			Auth: Auth{
				User: UserAuth{Methods: DefaultUserAuthMethods()},
				Target: TargetAuth{
					Method:    TargetAuthMethodStaticKey,
					StaticKey: StaticKeyAuth{KeyPath: "/etc/target_key"},
				},
			},
		}
	}

	tests := []struct {
		name      string
		mutate    func(*Config)
		wantField string
		wantCause error
	}{
		{
			// The management server addresses this bastion by id, including
			// its revocation stream: a nameless bastion cannot be told to kill
			// a session.
			name:      "missing bastion id",
			mutate:    func(c *Config) { c.Bastion.ID = "" },
			wantField: "bastion.id",
			wantCause: ErrMissing,
		},
		{
			name:      "unknown target auth method",
			mutate:    func(c *Config) { c.Auth.Target.Method = "ephemeral" },
			wantField: "auth.target.method",
			wantCause: ErrInvalid,
		},
		{
			name:      "static key without a key",
			mutate:    func(c *Config) { c.Auth.Target.StaticKey.KeyPath = "" },
			wantField: "auth.target.static_key.key_path",
			wantCause: ErrMissing,
		},
		{
			name:      "negative dial timeout",
			mutate:    func(c *Config) { c.Proxy.DialTimeout = -time.Second },
			wantField: "proxy.dial_timeout",
			wantCause: ErrInvalid,
		},
		{
			name:      "port out of range",
			mutate:    func(c *Config) { c.Proxy.DefaultTargetPort = 70000 },
			wantField: "proxy.default_target_port",
			wantCause: ErrInvalid,
		},
		{
			name:      "negative cache clamp",
			mutate:    func(c *Config) { c.Management.Cache.MaxTTL = -time.Minute },
			wantField: "management.cache.max_ttl",
			wantCause: ErrInvalid,
		},
		{
			// A bastion may run without a bearer token (development topologies
			// do), and the default cache settings mean "honour the server".
			name:   "token and cache are optional",
			mutate: func(c *Config) { c.Management.Token = "" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid()
			tt.mutate(&cfg)

			err := cfg.Validate()
			if tt.wantField == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("Validate() error = %v (%T), want *ValidationError", err, err)
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

// TestParseAppliesTargetAuthDefault checks the placeholder is what an operator
// gets by omission, and that it is still validated.
func TestParseAppliesTargetAuthDefault(t *testing.T) {
	cfg, err := Parse(strings.NewReader(minimalConfig))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if got, want := cfg.Auth.Target.Method, TargetAuthMethodStaticKey; got != want {
		t.Errorf("Auth.Target.Method = %q, want %q (default)", got, want)
	}
	if got := cfg.Proxy; got != (Proxy{}) {
		t.Errorf("Proxy = %+v, want the zero value (package defaults apply)", got)
	}
}

// TestExampleConfigCarriesTheProxySettings keeps the shipped example in step
// with the struct: the decoder is strict, so a field missing from one is a
// broken config for whoever copies the other.
func TestExampleConfigCarriesTheProxySettings(t *testing.T) {
	cfg, err := Load(exampleConfigPath)
	if err != nil {
		t.Fatalf("Load(%s): %v", exampleConfigPath, err)
	}
	if cfg.Bastion.ID == "" {
		t.Error("the example config does not set bastion.id")
	}
	if got, want := cfg.Proxy.DialTimeout, 15*time.Second; got != want {
		t.Errorf("Proxy.DialTimeout = %v, want %v", got, want)
	}
	if got, want := cfg.Proxy.DefaultTargetPort, 22; got != want {
		t.Errorf("Proxy.DefaultTargetPort = %d, want %d", got, want)
	}
	if got, want := cfg.Management.Cache.StaleAfter, 30*time.Second; got != want {
		t.Errorf("Management.Cache.StaleAfter = %v, want %v", got, want)
	}
	if got, want := cfg.Auth.Target.Method, TargetAuthMethodStaticKey; got != want {
		t.Errorf("Auth.Target.Method = %q, want %q", got, want)
	}
	if cfg.Auth.Target.StaticKey.KeyPath == "" {
		t.Error("the example config does not set auth.target.static_key.key_path")
	}
}
