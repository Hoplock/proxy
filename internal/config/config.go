// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Package config loads and validates the bastion's YAML bootstrap
// configuration (PLAN §8, D9).
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// DefaultTargetDelimiter separates the login from the target hostname in the
// SSH username, e.g. "alice#host.company.com" (D1).
const DefaultTargetDelimiter = "#"

// Config is the bastion's bootstrap configuration. It holds only what the
// bastion needs to start and reach the management server; every policy decision
// is made remotely (D2), so nothing policy-related belongs here.
type Config struct {
	Bastion    Bastion    `yaml:"bastion"`
	Management Management `yaml:"management"`
	Routing    Routing    `yaml:"routing"`
}

// Bastion describes the local SSH listener and this bastion's own identity.
type Bastion struct {
	// ListenAddr is the "host:port" the SSH listener binds to.
	ListenAddr string `yaml:"listen_addr"`
	// HostKeyPath is the path to the bastion's SSH host private key.
	HostKeyPath string `yaml:"host_key_path"`
}

// Management describes how to reach the management server (PDP).
type Management struct {
	// BaseURL is the root URL of the management API, e.g.
	// "https://mgmt.example.com".
	BaseURL string `yaml:"base_url"`
}

// Routing holds the rules for deriving the target from the SSH username (D1).
type Routing struct {
	// TargetDelimiter is the single character separating login from target in
	// the SSH username. Defaults to DefaultTargetDelimiter.
	TargetDelimiter string `yaml:"target_delimiter"`
}

// Sentinel causes, wrapped by FieldError so callers can classify a failure with
// errors.Is without string matching.
var (
	// ErrMissing indicates a required field was empty.
	ErrMissing = errors.New("required field is missing")
	// ErrInvalid indicates a field was set but its value is not usable.
	ErrInvalid = errors.New("field value is invalid")
	// ErrMalformed indicates the file could not be parsed as the expected YAML.
	ErrMalformed = errors.New("malformed configuration file")
)

// FieldError reports a single invalid configuration field. Field is the YAML
// path of the offending key (e.g. "bastion.listen_addr").
type FieldError struct {
	Field  string
	Detail string
	Cause  error
}

func (e *FieldError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("%s: %v", e.Field, e.Cause)
	}
	return fmt.Sprintf("%s: %v (%s)", e.Field, e.Cause, e.Detail)
}

// Unwrap exposes the sentinel cause to errors.Is.
func (e *FieldError) Unwrap() error { return e.Cause }

// ValidationError collects every field problem found in one pass so an operator
// can fix a config in a single edit instead of one restart per mistake.
type ValidationError struct {
	Fields []*FieldError
}

func (e *ValidationError) Error() string {
	parts := make([]string, 0, len(e.Fields))
	for _, f := range e.Fields {
		parts = append(parts, f.Error())
	}
	return "invalid configuration: " + strings.Join(parts, "; ")
}

// Unwrap lets errors.Is/errors.As reach the individual field errors.
func (e *ValidationError) Unwrap() []error {
	errs := make([]error, 0, len(e.Fields))
	for _, f := range e.Fields {
		errs = append(errs, f)
	}
	return errs
}

// Load reads, decodes, defaults, and validates the config file at path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	cfg, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes the config from r, applies defaults, and validates the result.
// Unknown keys are rejected: a typo in a security-relevant setting must fail
// loudly rather than silently fall back to a default.
func Parse(r io.Reader) (*Config, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: file is empty", ErrMalformed)
		}
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// applyDefaults fills in the values that have a safe, documented default.
func (c *Config) applyDefaults() {
	if c.Routing.TargetDelimiter == "" {
		c.Routing.TargetDelimiter = DefaultTargetDelimiter
	}
}

// Validate reports every problem with c as a *ValidationError.
func (c *Config) Validate() error {
	var v ValidationError

	if c.Bastion.ListenAddr == "" {
		v.add("bastion.listen_addr", ErrMissing, "")
	} else if _, _, err := net.SplitHostPort(c.Bastion.ListenAddr); err != nil {
		v.add("bastion.listen_addr", ErrInvalid, `expected "host:port"`)
	}

	if c.Bastion.HostKeyPath == "" {
		v.add("bastion.host_key_path", ErrMissing, "")
	}

	if c.Management.BaseURL == "" {
		v.add("management.base_url", ErrMissing, "")
	} else {
		u, err := url.Parse(c.Management.BaseURL)
		switch {
		case err != nil:
			v.add("management.base_url", ErrInvalid, "not a URL")
		case u.Scheme != "http" && u.Scheme != "https":
			v.add("management.base_url", ErrInvalid, "scheme must be http or https")
		case u.Host == "":
			v.add("management.base_url", ErrInvalid, "missing host")
		}
	}

	if err := validateDelimiter(c.Routing.TargetDelimiter); err != nil {
		v.add("routing.target_delimiter", ErrInvalid, err.Error())
	}

	if len(v.Fields) > 0 {
		return &v
	}
	return nil
}

func (v *ValidationError) add(field string, cause error, detail string) {
	v.Fields = append(v.Fields, &FieldError{Field: field, Detail: detail, Cause: cause})
}

// validateDelimiter enforces that the delimiter is a single character that
// cannot occur in a login name or a hostname, so splitting the SSH username is
// unambiguous (D1).
func validateDelimiter(d string) error {
	if utf8.RuneCountInString(d) != 1 {
		return errors.New("must be exactly one character")
	}
	r, _ := utf8.DecodeRuneInString(d)
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return errors.New("must not be alphanumeric")
	case r == '.', r == '-', r == '_':
		return errors.New("must not be a character valid in a hostname or login")
	}
	return nil
}
