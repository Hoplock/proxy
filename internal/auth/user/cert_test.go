// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package user

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
)

// testKey returns a fresh signer and its public key.
func testKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("building signer: %v", err)
	}
	return signer, signer.PublicKey()
}

func TestCertAuthenticatorAccepts(t *testing.T) {
	_, pub := testKey(t)

	rs, client := newRecordingServer(t, map[string]http.HandlerFunc{
		control.PathAuthenticateCert: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, control.AuthenticateResponse{
				Status:   control.AuthStatusAuthenticated,
				Identity: aliceIdentity(),
			})
		},
	})

	auth, err := NewCertAuthenticator(Options{Client: client})
	if err != nil {
		t.Fatalf("NewCertAuthenticator returned error: %v", err)
	}

	id, err := auth.AuthenticateCert(context.Background(), testMeta(), pub)
	if err != nil {
		t.Fatalf("AuthenticateCert returned error: %v", err)
	}

	if got, want := id.Subject, "alice@example.com"; got != want {
		t.Errorf("Subject = %q, want %q", got, want)
	}
	if got, want := id.Method, identity.MethodCert; got != want {
		t.Errorf("Method = %q, want %q", got, want)
	}
	if !id.HasGroup("sre") {
		t.Errorf("Groups = %v, want the server's groups to survive the conversion", id.Groups)
	}
	if id.AuthenticatedAt.IsZero() {
		t.Error("AuthenticatedAt is zero, want the time the proxy accepted the identity")
	}

	// The offered key must reach the server verbatim: the proxy validates
	// nothing locally, so anything it fails to send is a decision the server
	// could not make.
	bodies := rs.bodiesFor(control.PathAuthenticateCert)
	if len(bodies) != 1 {
		t.Fatalf("recorded %d requests, want 1", len(bodies))
	}
	body := bodies[0]
	for _, want := range []string{
		`"login":"alice"`,
		`"target":"db01.corp.example.com"`,
		ssh.FingerprintSHA256(pub),
		base64.StdEncoding.EncodeToString(pub.Marshal()),
		`"session_id":"sess-0001"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("request body = %s, want it to contain %q", body, want)
		}
	}
}

func TestCertAuthenticatorMarksCertificates(t *testing.T) {
	_, pub := testKey(t)
	caSigner, _ := testKey(t)

	cert := &ssh.Certificate{
		Key:         pub,
		CertType:    ssh.UserCert,
		KeyId:       "alice",
		ValidBefore: ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("signing certificate: %v", err)
	}

	rs, client := newRecordingServer(t, map[string]http.HandlerFunc{
		control.PathAuthenticateCert: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, control.AuthenticateResponse{
				Status:   control.AuthStatusAuthenticated,
				Identity: aliceIdentity(),
			})
		},
	})

	auth, err := NewCertAuthenticator(Options{Client: client})
	if err != nil {
		t.Fatalf("NewCertAuthenticator returned error: %v", err)
	}
	if _, err := auth.AuthenticateCert(context.Background(), testMeta(), cert); err != nil {
		t.Fatalf("AuthenticateCert returned error: %v", err)
	}

	// The server decides differently for a certificate than for a bare key, so
	// the distinction has to survive the conversion.
	if body := rs.bodiesFor(control.PathAuthenticateCert)[0]; !strings.Contains(body, `"is_certificate":true`) {
		t.Errorf("request body = %s, want it to mark the material as a certificate", body)
	}
}

func TestCertAuthenticatorOutcomes(t *testing.T) {
	_, pub := testKey(t)

	tests := []struct {
		name     string
		handler  http.HandlerFunc
		wantErr  error
		wantDeny bool
	}{
		{
			name: "denied",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeDeny(t, w, "unknown_key", "no such key")
			},
			wantErr:  ErrDenied,
			wantDeny: true,
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr: ErrUnavailable,
		},
		{
			// "Authenticated" with no identity is a contract violation, not a
			// decision: the proxy cannot audit a session it cannot attribute.
			name: "authenticated without an identity",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(t, w, http.StatusOK, map[string]any{"status": "authenticated"})
			},
			wantErr: ErrUnavailable,
		},
		{
			// Certificate auth that asks for a second factor is off-contract.
			name: "mfa requested",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(t, w, http.StatusOK, control.AuthenticateResponse{
					Status: control.AuthStatusMFARequired,
					MFA:    &control.MFAChallenge{Token: "tok", PollAfterMS: 10},
				})
			},
			wantErr: ErrUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, client := newRecordingServer(t, map[string]http.HandlerFunc{
				control.PathAuthenticateCert: tt.handler,
			})
			auth, err := NewCertAuthenticator(Options{Client: client})
			if err != nil {
				t.Fatalf("NewCertAuthenticator returned error: %v", err)
			}

			id, err := auth.AuthenticateCert(context.Background(), testMeta(), pub)
			if err == nil {
				t.Fatalf("AuthenticateCert() = %+v, want an error", id)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want errors.Is(..., %v)", err, tt.wantErr)
			}
			if got := IsDenied(err); got != tt.wantDeny {
				t.Errorf("IsDenied(%v) = %v, want %v", err, got, tt.wantDeny)
			}
		})
	}
}

// TestCertAuthenticatorUnreachableServerIsNotADeny is the fail-closed rule's
// other half: the session is refused either way, but an outage must never be
// classified as a permissions answer.
func TestCertAuthenticatorUnreachableServerIsNotADeny(t *testing.T) {
	_, pub := testKey(t)
	client := &fakeClient{
		certFn: func(context.Context, *control.AuthenticateCertRequest) (*control.AuthenticateResponse, error) {
			return nil, transportError("AuthenticateCert")
		},
	}

	auth, err := NewCertAuthenticator(Options{Client: client})
	if err != nil {
		t.Fatalf("NewCertAuthenticator returned error: %v", err)
	}

	_, err = auth.AuthenticateCert(context.Background(), testMeta(), pub)
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("error = %v, want errors.Is(..., ErrUnavailable)", err)
	}
	if IsDenied(err) {
		t.Errorf("IsDenied(%v) = true; an unreachable server is not a deny", err)
	}
}

func TestCertAuthenticatorRejectsMissingKey(t *testing.T) {
	client := &fakeClient{
		certFn: func(context.Context, *control.AuthenticateCertRequest) (*control.AuthenticateResponse, error) {
			t.Error("AuthenticateCert called without a key")
			return nil, nil
		},
	}
	auth, err := NewCertAuthenticator(Options{Client: client})
	if err != nil {
		t.Fatalf("NewCertAuthenticator returned error: %v", err)
	}

	if _, err := auth.AuthenticateCert(context.Background(), testMeta(), nil); !errors.Is(err, ErrDenied) {
		t.Errorf("error = %v, want errors.Is(..., ErrDenied)", err)
	}
}

func TestCertAuthenticatorHasNoPasswordFlow(t *testing.T) {
	client := &fakeClient{}
	auth, err := NewCertAuthenticator(Options{Client: client})
	if err != nil {
		t.Fatalf("NewCertAuthenticator returned error: %v", err)
	}

	if _, err := auth.AuthenticatePassword(context.Background(), testMeta(), "hunter2"); !errors.Is(err, ErrMethodNotSupported) {
		t.Errorf("error = %v, want errors.Is(..., ErrMethodNotSupported)", err)
	}
	if auth.SupportsPassword() || !auth.SupportsCert() {
		t.Errorf("SupportsCert/SupportsPassword = %v/%v, want true/false", auth.SupportsCert(), auth.SupportsPassword())
	}
	if got, want := auth.Name(), MethodCert; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestNewCertAuthenticatorRequiresClient(t *testing.T) {
	if _, err := NewCertAuthenticator(Options{}); err == nil {
		t.Fatal("NewCertAuthenticator without a client = nil error, want an error")
	}
}
