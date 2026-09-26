// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/config"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/sshtest"
)

// certTarget is a target that trusts one CA and nothing else — the device a
// brokered-certificate route reaches — together with that CA.
type certTarget struct {
	ca     *sshtest.CertificateAuthority
	target *sshtest.Target
}

func startCertTarget(t *testing.T) *certTarget {
	t.Helper()
	ca, err := sshtest.NewCertificateAuthority()
	if err != nil {
		t.Fatalf("NewCertificateAuthority: %v", err)
	}
	target, err := sshtest.StartTarget(sshtest.Options{TrustedUserCAKeys: []ssh.PublicKey{ca.PublicKey()}})
	if err != nil {
		t.Fatalf("StartTarget: %v", err)
	}
	t.Cleanup(func() { _ = target.Close() })
	return &certTarget{ca: ca, target: target}
}

// tgt names the target as a route would, on one rung of a brokered-certificate
// ladder carrying params.
func (c *certTarget) tgt(params map[string]string) Target {
	return Target{
		Host:            c.target.Host(),
		Port:            c.target.Port(),
		HostKeyCallback: ssh.FixedHostKey(c.target.HostKey()),
		SessionID:       "session-cert-1",
		DecisionID:      "decision-7",
		Auth:            &control.TargetAuth{Method: control.TargetAuthBrokeredCertificate, Params: params},
	}
}

// dial logs into the target with a provisioned configuration, the way the
// proxy's own dial does: the host-key policy is the caller's.
func (c *certTarget) dial(cfg *ssh.ClientConfig) error {
	dialCfg := *cfg
	dialCfg.HostKeyCallback = ssh.FixedHostKey(c.target.HostKey())
	dialCfg.Timeout = 20 * time.Second
	client, err := ssh.Dial("tcp", c.target.Addr().String(), &dialCfg)
	if err != nil {
		return err
	}
	return client.Close()
}

func newCertAuthenticator(t *testing.T, issuer control.CertificateIssuer, logger *log.Logger) *BrokeredCertificateAuthenticator {
	t.Helper()
	a, err := NewBrokeredCertificateAuthenticator(BrokeredCertificateOptions{Issuer: issuer, Logger: logger})
	if err != nil {
		t.Fatalf("NewBrokeredCertificateAuthenticator: %v", err)
	}
	return a
}

// TestBrokeredCertificateLogsInWithACertificateMintedForThisSession is the
// acceptance criterion end to end at this layer: a route naming the method and
// a username yields a session logged in under a certificate the authority
// minted for THIS session, over a key this process generated — proven by a real
// login against a target that trusts the CA and nothing else.
func TestBrokeredCertificateLogsInWithACertificateMintedForThisSession(t *testing.T) {
	c := startCertTarget(t)
	a := newCertAuthenticator(t, c.ca, nil)

	access, err := a.Provision(context.Background(), testIdentity(), c.tgt(map[string]string{
		ParamUsername:        "netadmin",
		ParamLifetimeSeconds: "600",
	}))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = access.Close(context.Background()) })

	if got := access.ClientConfig.User; got != "netadmin" {
		t.Errorf("login = %q, want the route's username", got)
	}
	if err := c.dial(access.ClientConfig); err != nil {
		t.Fatalf("the certificate did not log in: %v", err)
	}

	// The target accepted a CERTIFICATE, and it is the one the record names.
	serials := c.target.CertificateSerials()
	if len(serials) != 1 || strconv.FormatUint(serials[0], 10) != access.CertificateSerial {
		t.Errorf("target accepted serials %v, want exactly the recorded one %q", serials, access.CertificateSerial)
	}
	offered, ok := c.target.Keys()[len(c.target.Keys())-1].(*ssh.Certificate)
	if !ok {
		t.Fatalf("the target was offered a %T, want a certificate", c.target.Keys()[len(c.target.Keys())-1])
	}

	// The issuance carried the session's correlation and the route's account,
	// and the key it submitted is the key the certificate certifies.
	requests := c.ca.Requests()
	if len(requests) != 1 {
		t.Fatalf("%d issuance requests, want one per session", len(requests))
	}
	req := requests[0]
	if req.SessionID != "session-cert-1" || req.DecisionID != "decision-7" ||
		req.Target != c.target.Host() || req.Username != "netadmin" {
		t.Errorf("issuance request = %+v, want the session, decision, target and username", req)
	}
	submitted, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		t.Fatalf("the submitted public key does not parse: %v", err)
	}
	if !bytes.Equal(submitted.Marshal(), offered.Key.Marshal()) {
		t.Error("the certificate the target saw is not over the key this session submitted")
	}
	if submitted.Type() != ssh.KeyAlgoED25519 {
		t.Errorf("session key is %s, want the default ed25519", submitted.Type())
	}
}

// TestEachSessionGetsItsOwnKeyAndCertificate: the method is per SESSION. Two
// provisions from one route — as a cached decision reused for two connections
// produces — are two key pairs and two certificates, never one replayed.
func TestEachSessionGetsItsOwnKeyAndCertificate(t *testing.T) {
	c := startCertTarget(t)
	a := newCertAuthenticator(t, c.ca, nil)
	params := map[string]string{ParamUsername: "netadmin"}

	first, err := a.Provision(context.Background(), testIdentity(), c.tgt(params))
	if err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	second, err := a.Provision(context.Background(), testIdentity(), c.tgt(params))
	if err != nil {
		t.Fatalf("second Provision: %v", err)
	}
	if first.CertificateSerial == second.CertificateSerial {
		t.Errorf("two sessions presented one serial %q: the certificate was replayed", first.CertificateSerial)
	}
	requests := c.ca.Requests()
	if len(requests) != 2 || requests[0].PublicKey == requests[1].PublicKey {
		t.Errorf("issuance requests = %d with keys equal=%v; want two, over two different keys",
			len(requests), len(requests) == 2 && requests[0].PublicKey == requests[1].PublicKey)
	}
}

// TestACertificateThatFailsACheckIsAnOutageAndTheNextRungIsNotTried is the
// table the prompt requires: every verification failure ends the session as an
// outage, names its check, provisions nothing — and the selector does NOT walk
// on to the standing credential ranked below, which would be the silent
// downgrade D14 forbids.
func TestACertificateThatFailsACheckIsAnOutageAndTheNextRungIsNotTried(t *testing.T) {
	for _, tc := range []struct {
		fault sshtest.CertificateFault
		check string
	}{
		{sshtest.CertificateFaultWrongKey, "does not certify the key this session submitted"},
		{sshtest.CertificateFaultMalformed, "does not parse"},
		{sshtest.CertificateFaultExpired, "already expired"},
		{sshtest.CertificateFaultTooLong, "valid for longer than the route's lifetime_seconds"},
		{sshtest.CertificateFaultHostCertificate, "not a user certificate"},
		{sshtest.CertificateFaultMismatchedExpiry, "valid_before does not match"},
		{sshtest.CertificateFaultForever, "never expires"},
		{sshtest.CertificateFaultPlainKey, "a plain public key, not a certificate"},
	} {
		t.Run(string(tc.fault), func(t *testing.T) {
			c := startCertTarget(t)
			c.ca.SetFault(tc.fault)
			var logs bytes.Buffer
			cert := newCertAuthenticator(t, c.ca, log.New(&logs, "", 0))
			var generated *sessionKey
			cert.keys = func(keyType string) (*sessionKey, error) {
				k, err := newSessionKey(keyType)
				generated = k
				return k, err
			}
			standing := &recordingAuth{name: MethodBrokeredKey}
			selector, err := NewSelector(map[string]TargetAuthenticator{
				MethodBrokeredCertificate: cert,
				MethodBrokeredKey:         standing,
			}, MethodBrokeredKey, nil)
			if err != nil {
				t.Fatalf("NewSelector: %v", err)
			}

			tgt := c.tgt(nil)
			tgt.Auth = nil
			tgt.Ladder = &control.TargetAuthLadder{
				{Method: control.TargetAuthBrokeredCertificate, Params: map[string]string{
					ParamUsername: "netadmin", ParamLifetimeSeconds: "300",
				}},
				{Method: control.TargetAuthBrokeredKey, Params: map[string]string{ParamUsername: "netadmin"}},
			}
			access, err := selector.Provision(context.Background(), testIdentity(), tgt)
			if err == nil {
				_ = access.Close(context.Background())
				t.Fatal("a certificate that fails its check was used")
			}
			if !errors.Is(err, ErrCertificateUnavailable) {
				t.Errorf("error = %v, want ErrCertificateUnavailable", err)
			}
			if control.IsUnauthorized(err) {
				t.Errorf("error = %v reads as a DENIAL; a certificate the proxy refused is an outage", err)
			}
			if !strings.Contains(err.Error(), tc.check) {
				t.Errorf("error = %q, want it to name the check %q", err, tc.check)
			}
			if standing.calls != 0 {
				t.Error("the selector walked on to the standing credential after a failed issuance")
			}
			if generated == nil || !allZero(generated.ed) {
				t.Error("the session key survived a refused certificate")
			}
			// The error names the check and never the credential.
			for _, req := range c.ca.Requests() {
				body := strings.Fields(req.PublicKey)[1]
				if strings.Contains(err.Error(), body) || strings.Contains(logs.String(), body) {
					t.Error("the session's public key reached an error or a log line")
				}
			}
		})
	}
}

// TestAFailedIssuanceIsAnOutageNeverADenialAndNeverAWalk covers the other half
// of the failure rule: Control refusing, or not answering. A 401 from the
// issuance endpoint is the case that matters most — the authorization decision
// was already made, so it must not surface to the user as "access denied", and
// the ladder must not be walked while Control is least able to object.
func TestAFailedIssuanceIsAnOutageNeverADenialAndNeverAWalk(t *testing.T) {
	for name, issuerErr := range map[string]error{
		"a refusal (401)":        &control.APIError{Op: "IssueCertificate", StatusCode: 401, Cause: control.ErrUnauthorized},
		"no authority (503)":     &control.APIError{Op: "IssueCertificate", StatusCode: 503, Cause: control.ErrServer},
		"Control unreachable":    &control.APIError{Op: "IssueCertificate", Cause: control.ErrTransport},
		"an unreadable answer":   &control.APIError{Op: "IssueCertificate", Cause: control.ErrProtocol},
		"a bad request (400)":    &control.APIError{Op: "IssueCertificate", StatusCode: 400, Cause: control.ErrBadRequest},
		"a context cancellation": context.Canceled,
	} {
		t.Run(name, func(t *testing.T) {
			c := startCertTarget(t)
			c.ca.SetError(issuerErr)
			standing := &recordingAuth{name: MethodBrokeredKey}
			selector, err := NewSelector(map[string]TargetAuthenticator{
				MethodBrokeredCertificate: newCertAuthenticator(t, c.ca, nil),
				MethodBrokeredKey:         standing,
			}, MethodBrokeredKey, nil)
			if err != nil {
				t.Fatalf("NewSelector: %v", err)
			}
			tgt := c.tgt(nil)
			tgt.Auth = nil
			tgt.Ladder = &control.TargetAuthLadder{
				{Method: control.TargetAuthBrokeredCertificate, Params: map[string]string{ParamUsername: "netadmin"}},
				{Method: control.TargetAuthBrokeredKey, Params: map[string]string{ParamUsername: "netadmin"}},
			}
			_, err = selector.Provision(context.Background(), testIdentity(), tgt)
			if !errors.Is(err, ErrCertificateUnavailable) {
				t.Fatalf("error = %v, want ErrCertificateUnavailable", err)
			}
			if control.IsUnauthorized(err) {
				t.Errorf("error = %v reads as a denial", err)
			}
			if !strings.Contains(err.Error(), "issuance failed") {
				t.Errorf("error = %q, want it to say the issuance failed", err)
			}
			if standing.calls != 0 {
				t.Error("a failed issuance walked on to the next rung")
			}
		})
	}
}

// TestANilIssuerSkipsTheRung: a build with no issuer has no material for the
// method, so NewFromConfig does not construct it and the ordinary D14 walk
// passes the rung over — the ONE way this method is skipped.
func TestANilIssuerSkipsTheRung(t *testing.T) {
	dir := t.TempDir()
	build := func(issuer control.CertificateIssuer) *Selector {
		t.Helper()
		auth, err := NewFromConfig(config.TargetAuth{
			Method:      config.TargetAuthMethodBrokeredKey,
			BrokeredKey: config.BrokeredKeyAuth{Dir: dir},
		}, Options{ProxyID: "proxy-a", Issuer: issuer})
		if err != nil {
			t.Fatalf("NewFromConfig: %v", err)
		}
		return auth.(*Selector)
	}
	if got := build(nil).available(); strings.Contains(strings.Join(got, ","), MethodBrokeredCertificate) {
		t.Errorf("available methods = %v; a build with no issuer constructed brokered-certificate", got)
	}
	ca, err := sshtest.NewCertificateAuthority()
	if err != nil {
		t.Fatalf("NewCertificateAuthority: %v", err)
	}
	if got := build(ca).available(); !strings.Contains(strings.Join(got, ","), MethodBrokeredCertificate) {
		t.Errorf("available methods = %v; a build with an issuer did not construct brokered-certificate", got)
	}

	// And the walk: the certificate rung is skipped, the standing one serves.
	standing := &recordingAuth{name: MethodBrokeredKey}
	selector, err := NewSelector(map[string]TargetAuthenticator{MethodBrokeredKey: standing}, MethodBrokeredKey, nil)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	access, err := selector.Provision(context.Background(), testIdentity(), Target{
		Host: "edge-fw-01.company.com",
		Port: 22,
		Ladder: &control.TargetAuthLadder{
			{Method: control.TargetAuthBrokeredCertificate, Params: map[string]string{ParamUsername: "netadmin"}},
			{Method: control.TargetAuthBrokeredKey, Params: map[string]string{ParamUsername: "netadmin"}},
		},
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if standing.calls != 1 || access.Rung != 2 {
		t.Errorf("standing rung calls = %d, rung in force = %d; want the certificate rung skipped and rung 2 used",
			standing.calls, access.Rung)
	}
}

// TestBrokeredCertificateTeardownZeroesTheKey is the teardown guarantee: the
// only thing this method holds is the session's private key, so the only thing
// it can destroy is that key — and it must, on both key types, however many
// times teardown runs.
func TestBrokeredCertificateTeardownZeroesTheKey(t *testing.T) {
	for _, keyType := range []string{KeyTypeEd25519, KeyTypeRSA} {
		t.Run(keyType, func(t *testing.T) {
			c := startCertTarget(t)
			a := newCertAuthenticator(t, c.ca, nil)
			var held *sessionKey
			a.keys = func(kt string) (*sessionKey, error) {
				k, err := newSessionKey(kt)
				held = k
				return k, err
			}
			access, err := a.Provision(context.Background(), testIdentity(), c.tgt(map[string]string{
				ParamUsername: "netadmin", ParamKeyType: keyType,
			}))
			if err != nil {
				t.Fatalf("Provision: %v", err)
			}
			if err := c.dial(access.ClientConfig); err != nil {
				t.Fatalf("the %s certificate did not log in: %v", keyType, err)
			}
			// The words behind each RSA component, taken BEFORE teardown: they
			// share the big.Ints' backing arrays, so what they read afterwards
			// is what is left in memory — not merely what the Ints report.
			var words [][]big.Word
			if held.rsa != nil {
				words = append(words, held.rsa.D.Bits())
				for _, prime := range held.rsa.Primes {
					words = append(words, prime.Bits())
				}
			}
			if err := access.Close(context.Background()); err != nil {
				t.Fatalf("teardown: %v", err)
			}
			switch keyType {
			case KeyTypeEd25519:
				if len(held.ed) == 0 || !allZero(held.ed) {
					t.Error("the ed25519 private key survived teardown")
				}
			case KeyTypeRSA:
				if len(words) < 3 {
					t.Fatalf("captured %d RSA components, want D and both primes", len(words))
				}
				for _, w := range words {
					for _, word := range w {
						if word != 0 {
							t.Fatal("an RSA private component survived teardown in memory")
						}
					}
				}
			}
			// Teardown runs on every exit path, so it runs more than once.
			if err := access.Close(context.Background()); err != nil {
				t.Errorf("second teardown = %v, want nil", err)
			}
		})
	}
}

// TestBrokeredCertificateRefusesARouteBeforeGeneratingAnything: a route this
// method cannot serve costs no key pair and no call to Control. That includes
// the shape this phase refused on purpose — the certificate carried as a ROUTE
// PARAMETER, which on a cacheable decision is a replayed credential.
func TestBrokeredCertificateRefusesARouteBeforeGeneratingAnything(t *testing.T) {
	for name, tc := range map[string]struct {
		params map[string]string
		want   error
	}{
		"no username":              {map[string]string{ParamLifetimeSeconds: "300"}, ErrNoAccountName},
		"a certificate as a param": {map[string]string{ParamUsername: "netadmin", "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA"}, ErrUnknownParam},
		"a serial as a param":      {map[string]string{ParamUsername: "netadmin", "certificate_serial": "10427"}, ErrUnknownParam},
		"a CA bundle as a param":   {map[string]string{ParamUsername: "netadmin", "ca_public_keys": "ssh-ed25519 AAAA"}, ErrUnknownParam},
		"an unreadable lifetime":   {map[string]string{ParamUsername: "netadmin", ParamLifetimeSeconds: "ten minutes"}, ErrInvalidParam},
		"an unknown key type":      {map[string]string{ParamUsername: "netadmin", ParamKeyType: "dsa"}, ErrInvalidParam},
		"no ladder entry at all":   {nil, ErrNoAccountName},
	} {
		t.Run(name, func(t *testing.T) {
			c := startCertTarget(t)
			a := newCertAuthenticator(t, c.ca, nil)
			tgt := c.tgt(tc.params)
			if tc.params == nil {
				tgt.Auth = nil
			}
			_, err := a.Provision(context.Background(), testIdentity(), tgt)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if n := len(c.ca.Requests()); n != 0 {
				t.Errorf("%d issuance requests were made for a route that could not be served", n)
			}
		})
	}
}

// TestAnAppliedRungIsRefusedBeforeIssuance: the method provisions nothing, so
// an applied rung cannot be rendered by it, and is refused before Control is
// asked for anything.
func TestAnAppliedRungIsRefusedBeforeIssuance(t *testing.T) {
	c := startCertTarget(t)
	a := newCertAuthenticator(t, c.ca, nil)
	tgt := c.tgt(map[string]string{ParamUsername: "netadmin"})
	tgt.Enforcement = &Enforcement{Execution: control.ExecutionAccountRestricted}
	if _, err := a.Provision(context.Background(), testIdentity(), tgt); !errors.Is(err, ErrRungUnavailable) {
		t.Fatalf("error = %v, want ErrRungUnavailable", err)
	}
	if n := len(c.ca.Requests()); n != 0 {
		t.Errorf("%d issuance requests were made for a route whose rung this method cannot carry", n)
	}
}

// TestTheCertificateAndKeyNeverReachALogLine is the disclosure criterion: the
// serial is the one fact about the credential that is written anywhere.
func TestTheCertificateAndKeyNeverReachALogLine(t *testing.T) {
	c := startCertTarget(t)
	var logs bytes.Buffer
	a := newCertAuthenticator(t, c.ca, log.New(&logs, "", 0))
	access, err := a.Provision(context.Background(), testIdentity(), c.tgt(map[string]string{ParamUsername: "netadmin"}))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = access.Close(context.Background()) })

	if !strings.Contains(logs.String(), "serial="+access.CertificateSerial) {
		t.Errorf("log = %q, want it to name the serial", logs.String())
	}
	signer := access.ClientConfig.Auth
	if len(signer) != 1 {
		t.Fatalf("%d auth methods, want exactly the certificate", len(signer))
	}
	submitted := strings.Fields(c.ca.Requests()[0].PublicKey)[1]
	if strings.Contains(logs.String(), submitted) {
		t.Error("the session's public key reached a log line")
	}
	raw, _ := base64.StdEncoding.DecodeString(submitted)
	if len(raw) > 0 && bytes.Contains(logs.Bytes(), raw) {
		t.Error("the session's public key bytes reached a log line")
	}
}

// TestTheCertificateHandleIsThePrincipal: the rejection breaker and its record
// name a HANDLE — the principal a certificate is minted for, which is what a
// target keeps refusing when it does not trust the CA — never material.
func TestTheCertificateHandleIsThePrincipal(t *testing.T) {
	a := newCertAuthenticator(t, &sshtest.CertificateAuthority{}, nil)
	named := Target{Auth: &control.TargetAuth{
		Method: control.TargetAuthBrokeredCertificate,
		Params: map[string]string{ParamUsername: "netadmin"},
	}}
	if got := a.CredentialHandle(named); got != "principal:netadmin" {
		t.Errorf("handle = %q, want the route's principal", got)
	}
	if got := a.CredentialHandle(Target{}); got != "" {
		t.Errorf("a route naming no account produced the handle %q; there is nothing to score", got)
	}
}

// TestNewBrokeredCertificateAuthenticatorNeedsAnIssuer: with no issuer the
// method cannot exist, which is exactly why NewFromConfig does not build it.
func TestNewBrokeredCertificateAuthenticatorNeedsAnIssuer(t *testing.T) {
	if _, err := NewBrokeredCertificateAuthenticator(BrokeredCertificateOptions{}); err == nil {
		t.Fatal("an authenticator with no issuer was built")
	}
}
