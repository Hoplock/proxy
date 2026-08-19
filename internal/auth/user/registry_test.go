// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package user

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/config"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
)

// stubAuthenticator is a UserAuthenticator with scripted answers, for the
// registry's dispatch rules.
type stubAuthenticator struct {
	name     string
	certFn   func() (*identity.Identity, error)
	passFn   func() (*identity.Identity, error)
	certHits int
	passHits int
}

func (s *stubAuthenticator) Name() string { return s.name }

func (s *stubAuthenticator) AuthenticateCert(context.Context, ConnMeta, ssh.PublicKey) (*identity.Identity, error) {
	s.certHits++
	if s.certFn == nil {
		return nil, errors.New(s.name + ": " + ErrMethodNotSupported.Error())
	}
	return s.certFn()
}

func (s *stubAuthenticator) AuthenticatePassword(context.Context, ConnMeta, string) (*identity.Identity, error) {
	s.passHits++
	if s.passFn == nil {
		return nil, ErrMethodNotSupported
	}
	return s.passFn()
}

func notSupported() (*identity.Identity, error) { return nil, ErrMethodNotSupported }

func testIdentity(method identity.Method) *identity.Identity {
	return &identity.Identity{
		Subject: "alice@example.com",
		Login:   "alice",
		Source:  "fixture",
		Method:  method,
	}
}

func TestRegistryDispatchesToTheRightFlow(t *testing.T) {
	certAuth := &stubAuthenticator{
		name:   MethodCert,
		certFn: func() (*identity.Identity, error) { return testIdentity(identity.MethodCert), nil },
		passFn: notSupported,
	}
	passAuth := &stubAuthenticator{
		name:   MethodPasswordMFA,
		certFn: notSupported,
		passFn: func() (*identity.Identity, error) { return testIdentity(identity.MethodPasswordMFA), nil },
	}

	r, err := NewRegistry(certAuth, passAuth)
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}

	id, err := r.AuthenticateCert(context.Background(), testMeta(), nil)
	if err != nil {
		t.Fatalf("AuthenticateCert returned error: %v", err)
	}
	if got, want := id.Method, identity.MethodCert; got != want {
		t.Errorf("Method = %q, want %q", got, want)
	}

	id, err = r.AuthenticatePassword(context.Background(), testMeta(), testPassword)
	if err != nil {
		t.Fatalf("AuthenticatePassword returned error: %v", err)
	}
	if got, want := id.Method, identity.MethodPasswordMFA; got != want {
		t.Errorf("Method = %q, want %q", got, want)
	}

	if got, want := r.Name(), MethodCert+","+MethodPasswordMFA; got != want {
		t.Errorf("Name() = %q, want %q (certificate first)", got, want)
	}
}

// TestRegistryPrefersUnavailableOverDenied pins the precedence rule: if any
// authenticator could not reach a decision, the failure is an outage, because
// only a decided deny may be shown to a user as a permissions problem.
func TestRegistryPrefersUnavailableOverDenied(t *testing.T) {
	denying := &stubAuthenticator{
		name:   "denying",
		certFn: func() (*identity.Identity, error) { return nil, ErrDenied },
	}
	broken := &stubAuthenticator{
		name:   "broken",
		certFn: func() (*identity.Identity, error) { return nil, ErrUnavailable },
	}

	r, err := NewRegistry(denying, broken)
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}

	_, err = r.AuthenticateCert(context.Background(), testMeta(), nil)
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("error = %v, want errors.Is(..., ErrUnavailable)", err)
	}
	if IsDenied(err) {
		t.Errorf("IsDenied(%v) = true, want false", err)
	}
	if denying.certHits != 1 || broken.certHits != 1 {
		t.Errorf("hits = %d/%d, want every authenticator to be tried", denying.certHits, broken.certHits)
	}
}

// TestRegistryReportsDenyWhenEveryoneDecided is the other side of that rule.
func TestRegistryReportsDenyWhenEveryoneDecided(t *testing.T) {
	first := &stubAuthenticator{name: "a", certFn: func() (*identity.Identity, error) { return nil, ErrDenied }}
	second := &stubAuthenticator{name: "b", certFn: func() (*identity.Identity, error) { return nil, ErrDenied }}

	r, err := NewRegistry(first, second)
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}

	_, err = r.AuthenticateCert(context.Background(), testMeta(), nil)
	if !IsDenied(err) {
		t.Errorf("IsDenied(%v) = false, want true", err)
	}
}

// TestRegistryStopsAtTheFirstSuccess keeps a fallback from running after the
// session is already authenticated.
func TestRegistryStopsAtTheFirstSuccess(t *testing.T) {
	first := &stubAuthenticator{
		name:   "a",
		certFn: func() (*identity.Identity, error) { return testIdentity(identity.MethodCert), nil },
	}
	second := &stubAuthenticator{
		name: "b",
		certFn: func() (*identity.Identity, error) {
			t.Error("second authenticator ran after a success")
			return nil, nil
		},
	}

	r, err := NewRegistry(first, second)
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}
	if _, err := r.AuthenticateCert(context.Background(), testMeta(), nil); err != nil {
		t.Fatalf("AuthenticateCert returned error: %v", err)
	}
	if second.certHits != 0 {
		t.Errorf("second authenticator hits = %d, want 0", second.certHits)
	}
}

func TestRegistryReportsMethodNotSupported(t *testing.T) {
	certOnly := &stubAuthenticator{
		name:   MethodCert,
		certFn: func() (*identity.Identity, error) { return testIdentity(identity.MethodCert), nil },
		passFn: notSupported,
	}

	r, err := NewRegistry(certOnly)
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}
	if _, err := r.AuthenticatePassword(context.Background(), testMeta(), testPassword); !errors.Is(err, ErrMethodNotSupported) {
		t.Errorf("error = %v, want errors.Is(..., ErrMethodNotSupported)", err)
	}
}

func TestNewRegistryRejectsBadInput(t *testing.T) {
	if _, err := NewRegistry(); err == nil {
		t.Error("NewRegistry() with no authenticators = nil error, want an error")
	}
	if _, err := NewRegistry(nil); err == nil {
		t.Error("NewRegistry(nil) = nil error, want an error")
	}
	dup := &stubAuthenticator{name: MethodCert}
	if _, err := NewRegistry(dup, &stubAuthenticator{name: MethodCert}); err == nil {
		t.Error("NewRegistry with duplicate names = nil error, want an error")
	}
}

// TestNewFromConfigOrdersCertificateFirst is the ordering guarantee: the config
// file is a set of enabled methods, and the order is the plan's.
func TestNewFromConfigOrdersCertificateFirst(t *testing.T) {
	client := &fakeClient{}

	for _, methods := range [][]string{
		{MethodCert, MethodPasswordMFA},
		{MethodPasswordMFA, MethodCert},
	} {
		r, err := NewFromConfig(config.UserAuth{Methods: methods}, Options{Client: client})
		if err != nil {
			t.Fatalf("NewFromConfig(%v) returned error: %v", methods, err)
		}
		if got, want := r.Name(), MethodCert+","+MethodPasswordMFA; got != want {
			t.Errorf("NewFromConfig(%v).Name() = %q, want %q", methods, got, want)
		}
		if !r.SupportsCert() || !r.SupportsPassword() {
			t.Errorf("NewFromConfig(%v) supports cert/password = %v/%v, want both", methods, r.SupportsCert(), r.SupportsPassword())
		}
	}
}

func TestNewFromConfigSelectsEnabledMethods(t *testing.T) {
	client := &fakeClient{}

	certOnly, err := NewFromConfig(config.UserAuth{Methods: []string{MethodCert}}, Options{Client: client})
	if err != nil {
		t.Fatalf("NewFromConfig returned error: %v", err)
	}
	if !certOnly.SupportsCert() || certOnly.SupportsPassword() {
		t.Errorf("certificate-only registry supports cert/password = %v/%v, want true/false",
			certOnly.SupportsCert(), certOnly.SupportsPassword())
	}
	if got, want := len(certOnly.Authenticators()), 1; got != want {
		t.Errorf("authenticators = %d, want %d", got, want)
	}

	passOnly, err := NewFromConfig(config.UserAuth{Methods: []string{MethodPasswordMFA}}, Options{Client: client})
	if err != nil {
		t.Fatalf("NewFromConfig returned error: %v", err)
	}
	if passOnly.SupportsCert() || !passOnly.SupportsPassword() {
		t.Errorf("password-only registry supports cert/password = %v/%v, want false/true",
			passOnly.SupportsCert(), passOnly.SupportsPassword())
	}
}

func TestNewFromConfigPassesMFATuning(t *testing.T) {
	r, err := NewFromConfig(config.UserAuth{
		Methods: []string{MethodPasswordMFA},
		MFA: config.MFA{
			MinPollInterval:  250 * time.Millisecond,
			ProgressInterval: 3 * time.Second,
			MaxWait:          90 * time.Second,
		},
	}, Options{Client: &fakeClient{}})
	if err != nil {
		t.Fatalf("NewFromConfig returned error: %v", err)
	}

	auth, ok := r.Authenticators()[0].(*PasswordMFAAuthenticator)
	if !ok {
		t.Fatalf("authenticator type = %T, want *PasswordMFAAuthenticator", r.Authenticators()[0])
	}
	want := PasswordMFAOptions{MinPollInterval: 250 * time.Millisecond, ProgressInterval: 3 * time.Second, MaxWait: 90 * time.Second}
	if auth.mfa != want {
		t.Errorf("mfa options = %+v, want %+v", auth.mfa, want)
	}
}

func TestNewFromConfigRejectsBadConfig(t *testing.T) {
	client := &fakeClient{}

	if _, err := NewFromConfig(config.UserAuth{Methods: []string{"kerberos"}}, Options{Client: client}); err == nil {
		t.Error("NewFromConfig with an unknown method = nil error, want an error")
	}
	if _, err := NewFromConfig(config.UserAuth{Methods: nil}, Options{Client: client}); err == nil {
		t.Error("NewFromConfig with no methods = nil error, want an error")
	}
	if _, err := NewFromConfig(config.UserAuth{Methods: []string{MethodCert}}, Options{}); err == nil {
		t.Error("NewFromConfig without a management client = nil error, want an error")
	}
}

// TestRegistryFallsBackFromCertificateToPassword is the end-to-end ordering
// requirement of PLAN §4.1, at the registry level: a rejected key must not end
// the conversation, and the password flow must still be able to authenticate
// the same connection.
func TestRegistryFallsBackFromCertificateToPassword(t *testing.T) {
	_, pub := testKey(t)

	_, client := newRecordingServer(t, map[string]http.HandlerFunc{
		control.PathAuthenticateCert: func(w http.ResponseWriter, _ *http.Request) {
			writeDeny(t, w, "unknown_key", "no")
		},
		control.PathAuthenticatePassword: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, control.AuthenticateResponse{
				Status:   control.AuthStatusAuthenticated,
				Identity: aliceIdentity(),
			})
		},
	})

	r, err := NewFromConfig(config.UserAuth{Methods: config.DefaultUserAuthMethods()}, Options{Client: client})
	if err != nil {
		t.Fatalf("NewFromConfig returned error: %v", err)
	}

	if _, err := r.AuthenticateCert(context.Background(), testMeta(), pub); !IsDenied(err) {
		t.Fatalf("AuthenticateCert error = %v, want a deny", err)
	}

	id, err := r.AuthenticatePassword(context.Background(), testMeta(), testPassword)
	if err != nil {
		t.Fatalf("AuthenticatePassword after a rejected key returned error: %v", err)
	}
	if got, want := id.Method, identity.MethodPasswordMFA; got != want {
		t.Errorf("Method = %q, want %q", got, want)
	}
}
