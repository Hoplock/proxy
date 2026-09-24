// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package sshalg

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/sshtest"
)

func TestApplyNeverLeavesAnAxisEmpty(t *testing.T) {
	var cfg ssh.ClientConfig
	Apply(&cfg, control.Algorithms{})
	def := control.AlgorithmProfileDefault.Algorithms()
	if !slices.Equal(cfg.KeyExchanges, def.KeyExchanges) || !slices.Equal(cfg.Ciphers, def.Ciphers) ||
		!slices.Equal(cfg.MACs, def.MACs) || !slices.Equal(cfg.HostKeyAlgorithms, def.HostKeys) {
		t.Fatalf("zero Algorithms applied %+v, want the default expansion on every axis", cfg)
	}

	legacy := control.AlgorithmProfileLegacyDevice.Algorithms()
	Apply(&cfg, legacy)
	if !slices.Equal(cfg.KeyExchanges, legacy.KeyExchanges) || !slices.Equal(cfg.HostKeyAlgorithms, legacy.HostKeys) {
		t.Fatalf("legacy-device applied %q / %q", cfg.KeyExchanges, cfg.HostKeyAlgorithms)
	}

	// A partial list fills only the missing axes.
	Apply(&cfg, control.Algorithms{Ciphers: []string{"aes256-ctr"}})
	if !slices.Equal(cfg.Ciphers, []string{"aes256-ctr"}) || !slices.Equal(cfg.MACs, def.MACs) {
		t.Fatalf("partial Algorithms applied ciphers %q MACs %q", cfg.Ciphers, cfg.MACs)
	}
}

func rsaSigner(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignerRestrictsRSAToTheProfile(t *testing.T) {
	key := rsaSigner(t)

	def, ok := Signer(key, control.AlgorithmProfileDefault.Algorithms()).(ssh.MultiAlgorithmSigner)
	if !ok {
		t.Fatal("default did not restrict the RSA signer")
	}
	if got := def.Algorithms(); !slices.Equal(got, []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512}) {
		t.Fatalf("default RSA signature algorithms = %q", got)
	}

	legacy := Signer(key, control.AlgorithmProfileLegacyRSASHA1.Algorithms()).(ssh.MultiAlgorithmSigner)
	if got := legacy.Algorithms(); !slices.Equal(got, []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA}) {
		t.Fatalf("legacy-rsa-sha1 RSA signature algorithms = %q", got)
	}

	ed := sshtest.MustGenerateSigner()
	if got := Signer(ed, control.Algorithms{}).(ssh.MultiAlgorithmSigner).Algorithms(); !slices.Equal(got, []string{ssh.KeyAlgoED25519}) {
		t.Fatalf("ed25519 signature algorithms = %q", got)
	}

	// A key the route permits nothing for is refused rather than passed through.
	none := Signer(ed, control.Algorithms{PublicKeyAuths: []string{ssh.KeyAlgoRSASHA256}})
	if algs := none.(ssh.MultiAlgorithmSigner).Algorithms(); len(algs) != 0 {
		t.Fatalf("a key with no permitted algorithm kept %q", algs)
	}
}

// server starts an in-process SSH server with the given config and returns its
// address; every connection is handshaken and then dropped.
func server(t *testing.T, cfg *ssh.ServerConfig) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				if sc, chans, reqs, err := ssh.NewServerConn(c, cfg); err == nil {
					go ssh.DiscardRequests(reqs)
					go func() {
						for ch := range chans {
							_ = ch.Reject(ssh.Prohibited, "no")
						}
					}()
					_ = sc.Wait()
				}
			}()
		}
	}()
	return l.Addr().String()
}

func dial(addr string, a control.Algorithms, signer ssh.Signer) error {
	cfg := &ssh.ClientConfig{
		User:            "u",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(Signer(signer, a))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	Apply(cfg, a)
	c, err := ssh.Dial("tcp", addr, cfg)
	if err == nil {
		_ = c.Close()
	}
	return err
}

// A target that verifies public-key signatures only with SHA-1 RSA is refused
// under the default profile and served under legacy-rsa-sha1 — the proof that
// the public-key axis is applied and not only declared.
func TestPublicKeyAuthAxisIsAppliedOnTheWire(t *testing.T) {
	cfg := &ssh.ServerConfig{
		PublicKeyAuthAlgorithms: []string{ssh.KeyAlgoRSA},
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(sshtest.MustGenerateSigner())
	addr := server(t, cfg)
	key := rsaSigner(t)

	if err := dial(addr, control.AlgorithmProfileDefault.Algorithms(), key); err == nil {
		t.Fatal("default authenticated with an SHA-1 RSA signature")
	}
	if err := dial(addr, control.AlgorithmProfileLegacyRSASHA1.Algorithms(), key); err != nil {
		t.Fatalf("legacy-rsa-sha1 did not authenticate: %v", err)
	}
}

func TestKeyExchangeAxisIsAppliedOnTheWire(t *testing.T) {
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.KeyExchanges = []string{"diffie-hellman-group14-sha1"}
	cfg.AddHostKey(sshtest.MustGenerateSigner())
	addr := server(t, cfg)
	key := sshtest.MustGenerateSigner()

	err := dial(addr, control.AlgorithmProfileDefault.Algorithms(), key)
	var neg *ssh.AlgorithmNegotiationError
	if !errors.As(err, &neg) || neg.What != "key exchange" {
		t.Fatalf("default against a SHA-1-only key exchange: %v, want an AlgorithmNegotiationError on key exchange", err)
	}
	if err := dial(addr, control.AlgorithmProfileLegacyDevice.Algorithms(), key); err != nil {
		t.Fatalf("legacy-device did not connect: %v", err)
	}
}

// A certificate signer is restricted by its underlying key's algorithms, which
// is what phase 0044's brokered certificate relies on.
func TestSignerRestrictsACertificateByItsKey(t *testing.T) {
	key := rsaSigner(t)
	ca := sshtest.MustGenerateSigner()
	cert := &ssh.Certificate{Key: key.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"u"},
		ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	certSigner, err := ssh.NewCertSigner(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	restricted, ok := Signer(certSigner, control.AlgorithmProfileDefault.Algorithms()).(ssh.MultiAlgorithmSigner)
	if !ok {
		t.Fatal("the certificate signer was not restricted")
	}
	if got := restricted.Algorithms(); !slices.Equal(got, []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512}) {
		t.Fatalf("default certificate signature algorithms = %q", got)
	}
	if restricted.PublicKey().Type() != ssh.CertAlgoRSAv01 {
		t.Fatalf("the restricted signer no longer presents the certificate: %s", restricted.PublicKey().Type())
	}
}
