// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target/device"
	"github.com/hoplock/proxy/internal/auth/target/device/fortios"
	"github.com/hoplock/proxy/internal/config"
)

// Options are the dependencies every target authenticator shares.
type Options struct {
	// ProxyID identifies this proxy. The ephemeral method needs it: the
	// accounts it creates are named after it, which is what keeps two proxies
	// serving one target from reaping each other's live sessions.
	ProxyID string
	// Logger receives provisioning and teardown events; nil discards them. It
	// is never given a private key or a password.
	Logger *log.Logger
	// Events receives the device method's account-mapping events and its sweep
	// failures (PLAN §5.3, D8). Nil means this proxy has no logging path, which
	// REFUSES any route whose driver declares a constrained account-name limit:
	// on such a platform the mapping event is the only place attribution
	// exists.
	Events DeviceEventSink
}

// NewFromConfig builds the proxy's target credential plane.
//
// Since contract v2 the METHOD is Hoplock Control's choice per route (D6a), so
// this does not build "the" authenticator any more: it builds every method this
// proxy has local material for and hands them to a Selector, which dispatches
// on the route's target_auth. `auth.target.method` becomes the fallback used
// when the server names none — which is what a v1 server implies.
//
// There is still no fallback BETWEEN methods, and that is the important part: a
// route naming a method with no material fails as an outage rather than being
// served by a different credential than the server chose.
func NewFromConfig(cfg config.TargetAuth, opts Options) (TargetAuthenticator, error) {
	methods := map[string]TargetAuthenticator{}

	if cfg.StaticKey.KeyPath != "" {
		method, err := NewStaticKeyAuthenticator(StaticKeyOptions{
			KeyPath:  cfg.StaticKey.KeyPath,
			Username: cfg.StaticKey.Username,
			Logger:   opts.Logger,
		})
		if err != nil {
			return nil, err
		}
		methods[MethodStaticKey] = method
	}

	if cfg.EphemeralUser.ManagementKeyPath != "" && cfg.EphemeralUser.ProvisioningUser != "" {
		method, err := newEphemeralFromConfig(cfg.EphemeralUser, opts)
		if err != nil {
			return nil, err
		}
		methods[MethodEphemeralUser] = method
	}

	if source, err := newCredentialSource(cfg.BrokeredKey); err != nil {
		return nil, err
	} else if source != nil {
		method, err := NewBrokeredKeyAuthenticator(BrokeredKeyOptions{
			Source:   source,
			Username: cfg.BrokeredKey.Username,
			Logger:   opts.Logger,
		})
		if err != nil {
			return nil, err
		}
		methods[MethodBrokeredKey] = method
	}

	if deviceConfigured(cfg.EphemeralAccount) {
		method, err := newDeviceAccountFromConfig(cfg.EphemeralAccount, opts)
		if err != nil {
			return nil, err
		}
		methods[MethodEphemeralAccount] = method
	}

	return NewSelector(methods, cfg.Method, opts.Logger)
}

// deviceConfigured reports whether this proxy has the material the device
// method needs.
func deviceConfigured(cfg config.EphemeralAccountAuth) bool {
	return cfg.AdminUser != "" && (cfg.PasswordEnv != "" || cfg.KeyPath != "")
}

// newDeviceAccountFromConfig assembles the device provisioner: the privileged
// login it makes to devices, and the platform drivers this build carries.
//
// The management password is read from the ENVIRONMENT rather than from the
// configuration file, once, at startup. A device administrator password in a
// config file is one in a backup, a bug report, and a container image layer;
// the environment is not private either, but it is not a file that gets
// committed by accident.
func newDeviceAccountFromConfig(cfg config.EphemeralAccountAuth, opts Options) (*DeviceAccountAuthenticator, error) {
	dialerOpts := device.SSHShellOptions{User: cfg.AdminUser}
	if cfg.PasswordEnv != "" {
		dialerOpts.Password = os.Getenv(cfg.PasswordEnv)
		if dialerOpts.Password == "" {
			return nil, fmt.Errorf("auth/target: ephemeral-account: %s is empty or unset", cfg.PasswordEnv)
		}
	}
	if cfg.KeyPath != "" {
		signer, err := loadSigner(cfg.KeyPath, "")
		if err != nil {
			return nil, err
		}
		dialerOpts.Signer = signer
	}
	dialer, err := device.NewSSHShellDialer(dialerOpts)
	if err != nil {
		return nil, err
	}

	drivers, err := newDriverRegistry(cfg, dialer)
	if err != nil {
		return nil, err
	}
	return NewDeviceAccountAuthenticator(DeviceAccountOptions{
		ProxyID:        opts.ProxyID,
		Drivers:        drivers,
		SourceAddress:  cfg.SourceAddress,
		AccessProfile:  cfg.AccessProfile,
		Events:         opts.Events,
		ReaperInterval: cfg.Reaper.Interval,
		ReaperGrace:    cfg.Reaper.Grace,
		Logger:         opts.Logger,
	})
}

// newDriverRegistry builds the platform registry this proxy serves routes from.
//
// It is separate from device.Shipped(), which holds DECLARATIONS so that
// device.CheckShipped can hold Hoplock's own drivers to D13's rule. A driver
// that serves a route needs a way to reach a device, and that is configuration.
func newDriverRegistry(cfg config.EphemeralAccountAuth, dialer device.ShellDialer) (*device.Registry, error) {
	registry := device.NewRegistry()
	wanted := map[string]bool{}
	for _, p := range cfg.Platforms {
		wanted[p] = true
	}
	for _, platform := range device.Shipped().Platforms() {
		if len(wanted) > 0 && !wanted[platform] {
			continue
		}
		switch platform {
		case fortios.PlatformFortiGate:
			if err := fortios.Register(registry, fortios.Options{
				Dialer:        dialer,
				AccessProfile: cfg.AccessProfile,
			}); err != nil {
				return nil, err
			}
		default:
			// Unreachable while every shipped platform has a case. It is an
			// error rather than a silent skip because the alternative is a
			// proxy that advertises a platform it cannot actually serve, and
			// Hoplock Control routes on what the proxy advertises.
			return nil, fmt.Errorf("auth/target: no way to build the shipped driver for platform %q", platform)
		}
	}
	for platform := range wanted {
		if _, err := registry.Lookup(platform); err != nil {
			return nil, fmt.Errorf("auth/target: auth.target.ephemeral_account.platforms names %q, which this build has no driver for", platform)
		}
	}
	return registry, nil
}

// newEphemeralFromConfig assembles the just-in-time provisioner from local
// material.
func newEphemeralFromConfig(cfg config.EphemeralUserAuth, opts Options) (*EphemeralAuthenticator, error) {
	signer, err := loadSigner(cfg.ManagementKeyPath, cfg.ManagementCertPath)
	if err != nil {
		return nil, err
	}
	dialer, err := NewSSHAdminDialer(SSHAdminOptions{
		Signer:  signer,
		User:    cfg.ProvisioningUser,
		Shell:   cfg.Shell,
		Timeout: cfg.Timeout,
	})
	if err != nil {
		return nil, err
	}
	return NewEphemeralAuthenticator(EphemeralOptions{
		ProxyID:        opts.ProxyID,
		Dialer:         dialer,
		HomeBase:       cfg.HomeBase,
		TargetShell:    cfg.TargetShell,
		KeyExpiry:      cfg.EphemeralKeyExpiry(),
		ReaperInterval: cfg.Reaper.Interval,
		ReaperGrace:    cfg.Reaper.Grace,
		Logger:         opts.Logger,
	})
}

// newCredentialSource builds the brokered-key material source, or nil when none
// is configured.
func newCredentialSource(cfg config.BrokeredKeyAuth) (CredentialSource, error) {
	switch cfg.Source {
	case config.BrokeredSourceEnv:
		prefix := cfg.EnvPrefix
		if prefix == "" {
			prefix = config.DefaultBrokeredEnvPrefix
		}
		return NewEnvCredentialSource(prefix)
	case config.BrokeredSourceDir, "":
		if cfg.Dir == "" {
			return nil, nil
		}
		return NewDirCredentialSource(cfg.Dir, cfg.FileSuffix)
	default:
		return nil, fmt.Errorf("%w: brokered credential source %q", ErrUnknownMethod, cfg.Source)
	}
}

// loadSigner reads a private key and, when one is configured, the certificate
// presented with it.
//
// The certificate is how D6 is meant to be deployed: targets trust a CA rather
// than a key, so rotating the proxy's management credential does not mean
// touching every host's authorized_keys — which is the operation D6 exists to
// stop doing by hand.
func loadSigner(keyPath, certPath string) (ssh.Signer, error) {
	pem, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("auth/target: read management key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		// x/crypto's error names the file's problem, never its contents.
		return nil, fmt.Errorf("auth/target: parse management key %q: %w", keyPath, err)
	}
	if certPath == "" {
		return signer, nil
	}

	blob, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("auth/target: read management certificate: %w", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(blob)
	if err != nil {
		return nil, fmt.Errorf("auth/target: parse management certificate %q: %w", certPath, err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("auth/target: %q is a public key, not a certificate", certPath)
	}
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, fmt.Errorf("auth/target: management certificate does not match its key: %w", err)
	}
	return certSigner, nil
}
