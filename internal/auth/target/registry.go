// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"fmt"
	"log"

	"github.com/hoplock/proxy/internal/config"
)

// Options are the dependencies every target authenticator shares.
type Options struct {
	// Logger receives provisioning and teardown events; nil discards them. It
	// is never given a private key or a password.
	Logger *log.Logger
}

// NewFromConfig builds the configured target authenticator.
//
// Unlike the user plane there is no registry of several implementations here:
// one connection has exactly one way into its target, and falling back to a
// second credential source would mean the proxy connecting as something other
// than what policy provisioned for this session.
func NewFromConfig(cfg config.TargetAuth, opts Options) (TargetAuthenticator, error) {
	switch cfg.Method {
	case config.TargetAuthMethodStaticKey:
		return NewStaticKeyAuthenticator(StaticKeyOptions{
			KeyPath:  cfg.StaticKey.KeyPath,
			Username: cfg.StaticKey.Username,
			Logger:   opts.Logger,
		})
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownMethod, cfg.Method)
	}
}
