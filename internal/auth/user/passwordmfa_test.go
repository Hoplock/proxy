// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package user

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mauroasilva/securecommandproxy/internal/identity"
	"github.com/mauroasilva/securecommandproxy/internal/mgmt"
)

// testPassword is deliberately unmistakable so a leak into a log or an error is
// impossible to miss.
const testPassword = "correct-horse-battery-staple-9f3a"

func newPasswordAuth(t *testing.T, client mgmt.Client, opts PasswordMFAOptions) *PasswordMFAAuthenticator {
	t.Helper()
	auth, err := NewPasswordMFAAuthenticator(Options{Client: client}, opts)
	if err != nil {
		t.Fatalf("NewPasswordMFAAuthenticator returned error: %v", err)
	}
	return auth
}

func TestPasswordAuthenticatorAcceptsWithoutMFA(t *testing.T) {
	rs, client := newRecordingServer(t, map[string]http.HandlerFunc{
		mgmt.PathAuthenticatePassword: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, mgmt.AuthenticateResponse{
				Status:   mgmt.AuthStatusAuthenticated,
				Identity: aliceIdentity(),
			})
		},
	})

	auth := newPasswordAuth(t, client, fastMFA())
	id, err := auth.AuthenticatePassword(context.Background(), testMeta(), testPassword)
	if err != nil {
		t.Fatalf("AuthenticatePassword returned error: %v", err)
	}
	if got, want := id.Method, identity.MethodPasswordMFA; got != want {
		t.Errorf("Method = %q, want %q", got, want)
	}
	if got, want := id.Subject, "alice@example.com"; got != want {
		t.Errorf("Subject = %q, want %q", got, want)
	}
	if got := rs.requests(mgmt.PathAuthenticatePassword); got != 1 {
		t.Errorf("password requests = %d, want 1", got)
	}
}

// TestPasswordAuthenticatorApprovesMFA drives the full out-of-band flow: the
// server asks for a second factor, holds for two polls, then approves.
func TestPasswordAuthenticatorApprovesMFA(t *testing.T) {
	const serverPrompt = "Approve the login request in Okta Verify on your phone."
	var polls atomic.Int32

	_, client := newRecordingServer(t, map[string]http.HandlerFunc{
		mgmt.PathAuthenticatePassword: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, mgmt.AuthenticateResponse{
				Status: mgmt.AuthStatusMFARequired,
				MFA: &mgmt.MFAChallenge{
					Token:       "tok-1",
					Prompt:      serverPrompt,
					PollAfterMS: 1,
					ExpiresAt:   time.Now().Add(time.Minute),
				},
			})
		},
		mgmt.PathPollMFA: func(w http.ResponseWriter, _ *http.Request) {
			if polls.Add(1) <= 2 {
				writeJSON(t, w, http.StatusOK, mgmt.AuthenticateResponse{
					Status: mgmt.AuthStatusMFARequired,
					MFA: &mgmt.MFAChallenge{
						Token:       "tok-1",
						Prompt:      serverPrompt,
						PollAfterMS: 1,
						ExpiresAt:   time.Now().Add(time.Minute),
					},
				})
				return
			}
			writeJSON(t, w, http.StatusOK, mgmt.AuthenticateResponse{
				Status:   mgmt.AuthStatusAuthenticated,
				Identity: aliceIdentity(),
			})
		},
	})

	prompter := &recordingPrompter{}
	ctx := WithMFAPrompter(context.Background(), prompter)

	auth := newPasswordAuth(t, client, fastMFA())
	id, err := auth.AuthenticatePassword(ctx, testMeta(), testPassword)
	if err != nil {
		t.Fatalf("AuthenticatePassword returned error: %v", err)
	}
	if got, want := id.Subject, "alice@example.com"; got != want {
		t.Errorf("Subject = %q, want %q", got, want)
	}

	challenges, waits := prompter.snapshot()
	if len(challenges) != 1 {
		t.Fatalf("challenges = %v, want exactly one", challenges)
	}
	// The server's own prompt is what the user sees: it is the only party that
	// knows which factor the user actually has.
	if challenges[0] != serverPrompt {
		t.Errorf("challenge = %q, want the server's prompt %q", challenges[0], serverPrompt)
	}
	// Waiting must be visible. A silent wait is indistinguishable from a hang,
	// which is the whole reason this flow rides keyboard-interactive.
	if len(waits) == 0 {
		t.Error("no progress messages during the wait, want at least one")
	}
	for _, w := range waits {
		if !strings.Contains(w, serverPrompt) {
			t.Errorf("progress message %q, want it to repeat the instruction", w)
		}
	}
	if got := polls.Load(); got != 3 {
		t.Errorf("polls = %d, want 3 (two pending, one approval)", got)
	}
}

// TestPasswordAuthenticatorRespectsPollAfter checks the bastion obeys the
// server's pacing rather than polling as fast as it can.
func TestPasswordAuthenticatorRespectsPollAfter(t *testing.T) {
	const pollAfter = 60 * time.Millisecond
	var polls atomic.Int32

	client := &fakeClient{
		passwordFn: func(context.Context, *mgmt.AuthenticatePasswordRequest) (*mgmt.AuthenticateResponse, error) {
			return &mgmt.AuthenticateResponse{
				Status: mgmt.AuthStatusMFARequired,
				MFA: &mgmt.MFAChallenge{
					Token:       "tok-1",
					PollAfterMS: int(pollAfter / time.Millisecond),
					ExpiresAt:   time.Now().Add(time.Minute),
				},
			}, nil
		},
		pollFn: func(context.Context, *mgmt.MFAPollRequest) (*mgmt.AuthenticateResponse, error) {
			if polls.Add(1) == 1 {
				return &mgmt.AuthenticateResponse{
					Status: mgmt.AuthStatusMFARequired,
					MFA:    &mgmt.MFAChallenge{Token: "tok-1", PollAfterMS: int(pollAfter / time.Millisecond)},
				}, nil
			}
			return &mgmt.AuthenticateResponse{Status: mgmt.AuthStatusAuthenticated, Identity: aliceIdentity()}, nil
		},
	}

	auth := newPasswordAuth(t, client, PasswordMFAOptions{MinPollInterval: time.Millisecond, MaxWait: 5 * time.Second})

	start := time.Now()
	if _, err := auth.AuthenticatePassword(context.Background(), testMeta(), testPassword); err != nil {
		t.Fatalf("AuthenticatePassword returned error: %v", err)
	}
	// Two polls, each preceded by the server's interval.
	if elapsed := time.Since(start); elapsed < 2*pollAfter {
		t.Errorf("two polls took %v, want at least %v — the server's poll_after_ms was not respected", elapsed, 2*pollAfter)
	}
}

func TestPasswordAuthenticatorOutcomes(t *testing.T) {
	expired := time.Now().Add(-time.Second)

	tests := []struct {
		name     string
		handlers map[string]http.HandlerFunc
		wantErr  error
		wantDeny bool
	}{
		{
			name: "password rejected",
			handlers: map[string]http.HandlerFunc{
				mgmt.PathAuthenticatePassword: func(w http.ResponseWriter, _ *http.Request) {
					writeDeny(t, w, "bad_credentials", "no")
				},
			},
			wantErr:  ErrDenied,
			wantDeny: true,
		},
		{
			name: "mfa refused",
			handlers: map[string]http.HandlerFunc{
				mgmt.PathAuthenticatePassword: func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(t, w, http.StatusOK, mgmt.AuthenticateResponse{
						Status: mgmt.AuthStatusMFARequired,
						MFA:    &mgmt.MFAChallenge{Token: "tok-1", PollAfterMS: 1, ExpiresAt: time.Now().Add(time.Minute)},
					})
				},
				mgmt.PathPollMFA: func(w http.ResponseWriter, _ *http.Request) {
					writeDeny(t, w, "mfa_denied", "user refused")
				},
			},
			wantErr:  ErrDenied,
			wantDeny: true,
		},
		{
			// An unapproved challenge is a failed authentication, and the user
			// is told only "access denied" — the same as a wrong password.
			name: "mfa never approved",
			handlers: map[string]http.HandlerFunc{
				mgmt.PathAuthenticatePassword: func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(t, w, http.StatusOK, mgmt.AuthenticateResponse{
						Status: mgmt.AuthStatusMFARequired,
						MFA:    &mgmt.MFAChallenge{Token: "tok-1", PollAfterMS: 1, ExpiresAt: expired},
					})
				},
				mgmt.PathPollMFA: func(w http.ResponseWriter, _ *http.Request) {
					t.Error("polled a challenge that had already expired")
					writeDeny(t, w, "expired", "expired")
				},
			},
			wantErr:  ErrDenied,
			wantDeny: true,
		},
		{
			name: "server unreachable",
			handlers: map[string]http.HandlerFunc{
				mgmt.PathAuthenticatePassword: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusBadGateway)
				},
			},
			wantErr: ErrUnavailable,
		},
		{
			name: "mfa requested without a challenge",
			handlers: map[string]http.HandlerFunc{
				mgmt.PathAuthenticatePassword: func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(t, w, http.StatusOK, map[string]any{"status": "mfa_required"})
				},
			},
			wantErr: ErrUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, client := newRecordingServer(t, tt.handlers)
			auth := newPasswordAuth(t, client, fastMFA())

			id, err := auth.AuthenticatePassword(context.Background(), testMeta(), testPassword)
			if err == nil {
				t.Fatalf("AuthenticatePassword() = %+v, want an error", id)
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

// TestPasswordAuthenticatorStopsAtMaxWait bounds the wait even when the server
// hands out a challenge that never expires.
func TestPasswordAuthenticatorStopsAtMaxWait(t *testing.T) {
	client := &fakeClient{
		passwordFn: func(context.Context, *mgmt.AuthenticatePasswordRequest) (*mgmt.AuthenticateResponse, error) {
			return &mgmt.AuthenticateResponse{
				Status: mgmt.AuthStatusMFARequired,
				MFA:    &mgmt.MFAChallenge{Token: "tok-1", PollAfterMS: 1},
			}, nil
		},
		pollFn: func(context.Context, *mgmt.MFAPollRequest) (*mgmt.AuthenticateResponse, error) {
			return &mgmt.AuthenticateResponse{
				Status: mgmt.AuthStatusMFARequired,
				MFA:    &mgmt.MFAChallenge{Token: "tok-1", PollAfterMS: 1},
			}, nil
		},
	}

	auth := newPasswordAuth(t, client, PasswordMFAOptions{
		MinPollInterval:  time.Millisecond,
		ProgressInterval: -1, // silence progress; this test is about the bound
		MaxWait:          50 * time.Millisecond,
	})

	start := time.Now()
	_, err := auth.AuthenticatePassword(context.Background(), testMeta(), testPassword)
	if !errors.Is(err, ErrDenied) {
		t.Errorf("error = %v, want errors.Is(..., ErrDenied)", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("waited %v, want the wait bounded by MaxWait", elapsed)
	}
}

// TestPasswordAuthenticatorStopsWhenTheUserHangsUp covers the prompter failing:
// nobody is left to approve, and that is not a decision the server made.
func TestPasswordAuthenticatorStopsWhenTheUserHangsUp(t *testing.T) {
	client := &fakeClient{
		passwordFn: func(context.Context, *mgmt.AuthenticatePasswordRequest) (*mgmt.AuthenticateResponse, error) {
			return &mgmt.AuthenticateResponse{
				Status: mgmt.AuthStatusMFARequired,
				MFA:    &mgmt.MFAChallenge{Token: "tok-1", PollAfterMS: 1, ExpiresAt: time.Now().Add(time.Minute)},
			}, nil
		},
		pollFn: func(context.Context, *mgmt.MFAPollRequest) (*mgmt.AuthenticateResponse, error) {
			t.Error("polled after the user's client went away")
			return nil, nil
		},
	}

	prompter := &recordingPrompter{err: errors.New("client closed the connection")}
	ctx := WithMFAPrompter(context.Background(), prompter)

	auth := newPasswordAuth(t, client, fastMFA())
	_, err := auth.AuthenticatePassword(ctx, testMeta(), testPassword)
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("error = %v, want errors.Is(..., ErrUnavailable)", err)
	}
	if IsDenied(err) {
		t.Errorf("IsDenied(%v) = true; a dropped client is not a policy decision", err)
	}
}

// TestPasswordAuthenticatorHonoursContextCancellation makes sure a torn-down
// connection stops the polling loop instead of leaving it running.
func TestPasswordAuthenticatorHonoursContextCancellation(t *testing.T) {
	client := &fakeClient{
		passwordFn: func(context.Context, *mgmt.AuthenticatePasswordRequest) (*mgmt.AuthenticateResponse, error) {
			return &mgmt.AuthenticateResponse{
				Status: mgmt.AuthStatusMFARequired,
				MFA:    &mgmt.MFAChallenge{Token: "tok-1", PollAfterMS: 50, ExpiresAt: time.Now().Add(time.Minute)},
			}, nil
		},
		pollFn: func(ctx context.Context, _ *mgmt.MFAPollRequest) (*mgmt.AuthenticateResponse, error) {
			return nil, ctx.Err()
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	auth := newPasswordAuth(t, client, fastMFA())
	_, err := auth.AuthenticatePassword(ctx, testMeta(), testPassword)
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("error = %v, want errors.Is(..., ErrUnavailable)", err)
	}
}

// TestPasswordNeverReachesLogsOrErrors is the redaction requirement (PLAN §7).
// It runs the whole password+MFA flow with logging on and then searches every
// artefact the bastion produced for the password.
func TestPasswordNeverReachesLogsOrErrors(t *testing.T) {
	var polls atomic.Int32

	rs, client := newRecordingServer(t, map[string]http.HandlerFunc{
		mgmt.PathAuthenticatePassword: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, mgmt.AuthenticateResponse{
				Status: mgmt.AuthStatusMFARequired,
				MFA: &mgmt.MFAChallenge{
					Token:       "tok-1",
					Prompt:      "Approve on your phone.",
					PollAfterMS: 1,
					ExpiresAt:   time.Now().Add(time.Minute),
				},
			})
		},
		mgmt.PathPollMFA: func(w http.ResponseWriter, _ *http.Request) {
			if polls.Add(1) == 1 {
				writeJSON(t, w, http.StatusOK, mgmt.AuthenticateResponse{
					Status: mgmt.AuthStatusMFARequired,
					MFA:    &mgmt.MFAChallenge{Token: "tok-1", PollAfterMS: 1, ExpiresAt: time.Now().Add(time.Minute)},
				})
				return
			}
			// End on a deny, so the failure path is exercised too: an error
			// string is just as public as a log line.
			writeDeny(t, w, "mfa_denied", "user refused")
		},
	})

	logger, logs := testLogger()
	prompter := &recordingPrompter{}
	auth, err := NewPasswordMFAAuthenticator(Options{Client: client, Logger: logger}, fastMFA())
	if err != nil {
		t.Fatalf("NewPasswordMFAAuthenticator returned error: %v", err)
	}

	_, authErr := auth.AuthenticatePassword(WithMFAPrompter(context.Background(), prompter), testMeta(), testPassword)
	if authErr == nil {
		t.Fatal("AuthenticatePassword = nil error, want the deny")
	}

	// Sanity check the test itself: the password must really have been in play,
	// or "it is absent from the logs" proves nothing.
	sent := rs.bodiesFor(mgmt.PathAuthenticatePassword)
	if len(sent) != 1 || !strings.Contains(sent[0], testPassword) {
		t.Fatalf("password was not sent to the management server; bodies = %q", sent)
	}

	if logs.Len() == 0 {
		t.Fatal("no log output, so the redaction assertion would be vacuous")
	}
	if strings.Contains(logs.String(), testPassword) {
		t.Errorf("password appeared in the logs:\n%s", logs.String())
	}
	if strings.Contains(authErr.Error(), testPassword) {
		t.Errorf("password appeared in the error: %v", authErr)
	}
	challenges, waits := prompter.snapshot()
	for _, msg := range append(challenges, waits...) {
		if strings.Contains(msg, testPassword) {
			t.Errorf("password appeared in a user-visible message: %q", msg)
		}
	}
	// The user-facing failure text is generated from the error; check it too.
	if msg := FailureMessage(authErr, testMeta().SessionID); strings.Contains(msg, testPassword) {
		t.Errorf("password appeared in the user-facing message: %q", msg)
	}
}

func TestPasswordAuthenticatorHasNoCertFlow(t *testing.T) {
	auth := newPasswordAuth(t, &fakeClient{}, fastMFA())

	if _, err := auth.AuthenticateCert(context.Background(), testMeta(), nil); !errors.Is(err, ErrMethodNotSupported) {
		t.Errorf("error = %v, want errors.Is(..., ErrMethodNotSupported)", err)
	}
	if auth.SupportsCert() || !auth.SupportsPassword() {
		t.Errorf("SupportsCert/SupportsPassword = %v/%v, want false/true", auth.SupportsCert(), auth.SupportsPassword())
	}
	if got, want := auth.Name(), MethodPasswordMFA; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestNewPasswordMFAAuthenticatorRequiresClient(t *testing.T) {
	if _, err := NewPasswordMFAAuthenticator(Options{}, PasswordMFAOptions{}); err == nil {
		t.Fatal("NewPasswordMFAAuthenticator without a client = nil error, want an error")
	}
}

func TestPasswordMFAOptionDefaults(t *testing.T) {
	got := PasswordMFAOptions{}.withDefaults()
	want := PasswordMFAOptions{
		MinPollInterval:  DefaultMinPollInterval,
		ProgressInterval: DefaultProgressInterval,
		MaxWait:          DefaultMaxWait,
	}
	if got != want {
		t.Errorf("withDefaults() = %+v, want %+v", got, want)
	}
	// A negative progress interval is "never talk", not "talk constantly".
	if got := (PasswordMFAOptions{ProgressInterval: -1}).withDefaults(); got.ProgressInterval != -1 {
		t.Errorf("ProgressInterval = %v, want it left disabled", got.ProgressInterval)
	}
}
